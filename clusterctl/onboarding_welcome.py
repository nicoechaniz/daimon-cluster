"""One approved first welcome, with durable reconciliation of uncertain sends.

This host adapter never consumes Telegram ingress or starts a model turn.
A lost external acknowledgement remains uncertain rather than being replayed.
"""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request

from . import being_seed
from .onboarding import Observation, OnboardingError, digest, private_directory, validate_plan
from .onboarding_telegram import connections, reserve

SCHEMA = 'cluster-onboarding-welcome/v1'


def text(plan: dict) -> str:
    validate_plan(plan)
    return (f"El cuerpo de {plan['name'].capitalize()} en daimon-cluster ya tiene Matrix, memoria, "
            "SSH y Codex configurados. Este es el aviso del servicio de alta.\n\n"
            "Para verificar la conversación, mandá un mensaje aquí y creá dos temas con "
            "/topic Memoria y /topic Trabajo. Comprobá que reconozca su identidad y pueda "
            "recuperar una memoria antigua y una reciente. Durante una respuesta, mandá "
            "una corrección y verificá que se incorpore. Conservamos el historial original.\n\n"
            "Las pruebas de reinicio, continuidad y acceso todavía deben completarse; "
            "este aviso no declara terminado el alta. El mismo sitio de alta muestra el estado.")


def send(token: str, human: int, message: str) -> dict:
    try:
        payload = json.dumps(dict(chat_id=human, text=message)).encode()
        request = urllib.request.Request('https://api.telegram.org/bot' + token + '/sendMessage',
                                         data=payload, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(65537)
        value = json.loads(raw)
        if (len(raw) > 65536 or not isinstance(value, dict) or value.get('ok') is not True
                or not isinstance(value.get('result'), dict)):
            raise ValueError
        return value['result']
    except (OSError, ValueError, urllib.error.URLError):
        # The request may have reached Telegram: preserve intent and do not
        # disclose the credential-bearing URL or vendor response.
        raise OnboardingError('uncertain_external_effect') from None


class Welcome:
    def __init__(self, host, *, request=send):
        self.host = host
        self.request = request

    def _binding(self, plan: dict) -> tuple[dict, dict]:
        validate_plan(plan)
        if not self.host.authorize(plan, digest(plan)):
            raise OnboardingError('host_authorization_required')
        supplied = self.host._telegram_connections(plan)
        if supplied is None:
            raise OnboardingError('connection_data_required')
        supplied = connections(supplied)
        bot = int(supplied['telegram_bot_token'].split(':', 1)[0])
        binding = dict(schema=SCHEMA, plan_digest=digest(plan), bot_id=bot,
                       destination_digest=digest({'human': supplied['telegram_chat_id']}),
                       text_sha256=hashlib.sha256(text(plan).encode()).hexdigest())
        return supplied, binding

    def _directory(self, plan: dict):
        # JobStore already owns its job lock; this separate subdirectory has
        # a distinct lock and does not deadlock the enclosing stage dispatch.
        parent = private_directory(self.host.config.jobs / plan['name'])
        return private_directory(parent / 'welcome', create=True)

    @staticmethod
    def _observe(root, binding: dict) -> Observation:
        receipt = root / 'receipt.json'
        intent = root / 'intent.json'
        if intent.exists() and being_seed._read(intent) != binding:
            return Observation('conflict', reason='observed_state_conflict')
        if receipt.exists():
            value = being_seed._read(receipt)
            if (not intent.exists() or set(value) != set(binding) | {'message_id', 'telegram_acknowledged'}
                    or any(value.get(key) != expected for key, expected in binding.items())
                    or type(value.get('message_id')) is not int or value['message_id'] <= 0
                    or value.get('telegram_acknowledged') is not True):
                return Observation('conflict', reason='observed_state_conflict')
            # A Bot API acknowledgement proves transport acceptance. It does
            # not prove human contact, a model response or conversation tests.
            return Observation('complete', dict(verified=True, welcome_delivered=True))
        if intent.exists():
            return Observation('uncertain', reason='uncertain_external_effect')
        return Observation('absent', safe_to_execute=True)

    def observe(self, plan: dict) -> Observation:
        _, binding = self._binding(plan)
        root = self._directory(plan)
        with being_seed._locked(root):
            return self._observe(root, binding)

    def execute(self, plan: dict) -> None:
        supplied, binding = self._binding(plan)
        root = self._directory(plan)
        with being_seed._locked(root):
            observation = self._observe(root, binding)
            if observation.state == 'complete':
                return
            if observation.state != 'absent':
                raise OnboardingError(observation.reason)
            ready = self.host._telegram_command(plan, 'observe')
            if (ready.get('configured') is not True or ready.get('listening') is not True
                    or ready.get('plan_digest') != digest(plan) or ready.get('bot_id') != binding['bot_id']):
                raise OnboardingError('verification_failed')
            selected = self.host._telegram_binding(plan)
            if selected != dict(plan_digest=digest(plan), bot_id=binding['bot_id'],
                                destination_digest=binding['destination_digest'],
                                token_sha256=hashlib.sha256(supplied['telegram_bot_token'].encode()).hexdigest()):
                raise OnboardingError('observed_state_conflict')
            reserve(self.host.config.jobs, plan, supplied)
            # Recheck the current grant immediately before durable intent.
            if self._binding(plan)[1] != binding:
                raise OnboardingError('observed_state_conflict')
            being_seed._write(root / 'intent.json', binding)
            result = self.request(supplied['telegram_bot_token'], supplied['telegram_chat_id'], text(plan))
            if (type(result.get('message_id')) is not int or result['message_id'] <= 0
                    or result.get('chat', {}).get('id') != supplied['telegram_chat_id']
                    or result.get('chat', {}).get('type') != 'private'
                    or result.get('from', {}).get('id') != binding['bot_id']
                    or result.get('from', {}).get('is_bot') is not True or result.get('text') != text(plan)):
                raise OnboardingError('uncertain_external_effect')
            being_seed._write(root / 'receipt.json', {**binding, 'message_id': result['message_id'],
                                                     'telegram_acknowledged': True})
