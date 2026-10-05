"""A/B provider process. Authority package arrives from O, never from A."""
import json
import sys
import time
from protocol import *


def main():
    c = json.load(sys.stdin)
    key = private(c['worker_private'])
    token = c.get('token')
    if c['arm'] == 'OAUTH_EXCHANGE':
        client = c['worker']
        endpoint = c['authority_url'] + '/exchange'
        form = {'grant_type': EXCHANGE, 'subject_token': token,
                'subject_token_type': JWT_TYPE, 'requested_token_type': TOKEN_TYPE,
                'audience': RECEIVER, 'scope': 'refund', 'client_id': client,
                'client_assertion_type': ASSERTION,
                'client_assertion': issue(key, client, client, endpoint, 'JWT', ttl=5)}
        status, response = request(endpoint, form, form=True)
        if status != 200:
            raise RuntimeError('exchange_failed:' + response.get('error', 'unknown'))
        token = response['access_token']
        print(json.dumps({'exchange': {'request': form, 'response': response}}), flush=True)

    def attempt(amount=25):
        body = {'worker': c['worker'], 'job_id': JOB, 'amount_cents': amount}
        if c['arm'].startswith('OL_'):
            body['authorization'] = c['authorization']
        else:
            body['token'] = token
        body['worker_assertion'] = issue(key, c['worker'], c['worker'], RECEIVER,
                                        'worker-request+jwt',
                                        {'body_hash': digest(json_bytes(body))}, ttl=5)
        status, response = request(c['receiver_url'] + '/attempt', body)
        if status != 200:
            raise RuntimeError('receiver_failed')
        print(json.dumps({'attempt': response}), flush=True)
        event = jwt.decode(response['signed_event'], options={'verify_signature': False})['event']
        return event['allowed']

    # A performs one effect and stays alive until the supervisor permanently
    # terminates its whole provider process. B also probes the hard scope cap.
    if c['worker'] == 'A':
        if not attempt():
            raise RuntimeError('initial_A_not_accepted')
        while True:
            time.sleep(0.1)
    else:
        attempt()
        attempt(101)
        first_refusal = None
        while time.monotonic() < c['deadline']:
            accepted = attempt()
            if not accepted:
                if first_refusal is not None:
                    break
                first_refusal = time.monotonic()
                # Bound controls must stay alive through the scheduled STOP,
                # otherwise B's already-refused state would mask revocation.
                if c['arm'] in ('OL_BOUND', 'JWT_BOUND'):
                    time.sleep(max(0, c['revoke_after'] - time.monotonic() + 0.15))
            time.sleep(0.1)


if __name__ == '__main__':
    main()
