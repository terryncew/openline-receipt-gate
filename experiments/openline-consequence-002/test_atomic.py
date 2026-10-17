"""Reconstructed adversarial matrix; original CONSEQUENCE-001 spec is absent."""
import copy
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path
from fixtures import NOW, SUBJECT, fixture, key
from olp_gate.crypto import sign_olp_body
from olp_gate.mandate_owner import issue_mandate_authorization
from olp_gate.sqlite_consequence import SQLiteConsequence, initialize, canonical, digest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUTPUT = Path(os.environ.get('CONSEQUENCE_EVIDENCE', tempfile.mkdtemp(prefix='consequence-002-')))


class AtomicConsequenceTests(unittest.TestCase):
    implementation = 'openline'

    def setUp(self):
        self.root = OUTPUT / self.implementation / self._testMethodName
        self.root.mkdir(parents=True, exist_ok=False)
        self.f = fixture(self.root)
        (self.root/'fixture.json').write_text(canonical(self.f))
        (self.root/'roots.json').write_text(canonical(self.f['roots']))
        self.path = self.root/'state.sqlite3'
        initialize(self.path, roots=self.f['roots'], site=self.f['site'], artifacts=self.f['artifacts'],
                   policy_hash=self.f['policy_hash'], now=NOW, implementation=self.implementation)
        self.a = self.adapter()
        self.a.admit_owner(self.f['owner_authorization'], self.f['mandate'])
        self.workers = []
        self.expected_commits = 0
        self.expected_verifier = True

    def adapter(self, **overrides):
        options = dict(roots=self.f['roots'], subject_source=lambda: SUBJECT,
                       signing_key=key('74'), clock=lambda: NOW, implementation=self.implementation)
        options.update(overrides)
        return SQLiteConsequence(self.path, **options)

    def apply(self, adapter=None, f=None):
        f = f or self.f
        return (adapter or self.a).commission(f['receipt'], f['action'], one_use_code=f['code'])

    def sql(self, statement, args=()):
        with sqlite3.connect(self.path) as c:
            c.execute('PRAGMA foreign_keys=ON')
            c.execute('BEGIN IMMEDIATE')
            c.execute(statement, args)

    def rows(self):
        with sqlite3.connect(self.path) as c:
            c.row_factory = sqlite3.Row
            return {name: [dict(r) for r in c.execute('SELECT * FROM '+name)]
                    for name in ('receiver','sites','owner_history','artifacts','ledger','commitments')}

    def tearDown(self):
        rows = self.rows()  # actual rows after EVERY scenario, including failures
        (self.root/'rows.json').write_text(json.dumps(rows, indent=2, sort_keys=True)+'\n')
        (self.root/'workers.json').write_text(json.dumps(self.workers, indent=2)+'\n')
        commitments = rows['commitments']
        self.assertEqual(len(commitments), self.expected_commits)
        self.assertEqual(rows['sites'][0]['commissioned'], int(bool(commitments)))
        ledger = json.loads(rows['ledger'][0]['body'])
        self.assertEqual(len(ledger['consumed_decisions']), self.expected_commits if self.implementation=='openline' else 0)
        if (HERE/'verify.py').exists():
            run = subprocess.run([sys.executable, str(HERE/'verify.py'), str(self.path), '--roots', str(self.root/'roots.json')],
                                 cwd=REPO, text=True, capture_output=True)
            (self.root/'verifier.json').write_text(run.stdout)
            (self.root/'verifier.stderr').write_text(run.stderr)
            self.assertEqual(run.returncode, 0 if self.expected_verifier else 1, run.stdout+run.stderr)
        else:
            self.fail('independent verifier missing')

    def revoke(self):
        rev = issue_mandate_authorization(slot_id=self.f['roots']['slot_id'], owner_id=self.f['roots']['owner_id'],
            mandate=self.f['mandate'], state='REVOKED', sequence=2,
            predecessor_hash=self.f['owner_authorization']['payload_hash'], issued_at=NOW,
            expires_at=NOW+timedelta(minutes=5), key=key('71'))
        self.a.admit_owner(rev, self.f['mandate'])
        return rev

    def spawn(self, stage='none'):
        return subprocess.Popen([sys.executable, str(HERE/'worker.py'), str(self.root), self.implementation, stage],
                                cwd=REPO, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def collect(self, p, expected=0):
        out, err = p.communicate(timeout=20)
        self.workers.append(dict(exit_status=p.returncode, expected=expected, stdout=out, stderr=err))
        self.assertEqual(p.returncode, expected, out+err)
        return json.loads(out) if out else None

    def test_01_success_and_exact_idempotent_retry(self):
        self.assertEqual(self.apply()['status'], 'COMMITTED')
        self.expected_commits = 1
        self.assertEqual(self.apply(self.adapter())['status'], 'ALREADY_COMMITTED')

    def test_02_forgery_binding_and_code(self):
        for field, value in [('target','sqlite://commissioning/wrong'),('tool','sqlite.delete'),
                             ('run_id','wrong'),('capsule_hash','00'*32),('evidence_hashes',['00'*32])]:
            f=copy.deepcopy(self.f);f['action'][field]=value
            self.assertEqual(self.apply(f=f)['status'], 'REFUSED', field)
        for field in ['robot_config_digest','simulation_digest','mandate_hash','site_version','idempotency_key']:
            f=copy.deepcopy(self.f)
            f['action']['settings'][field] = 2 if field=='site_version' else 'changed'
            self.assertEqual(self.apply(f=f)['status'], 'REFUSED', field)
        f=copy.deepcopy(self.f);f['receipt']['decision']='DENY'
        self.assertEqual(self.apply(f=f)['status'], 'REFUSED')
        f=copy.deepcopy(self.f);f['code']='00'*32
        self.assertEqual(self.apply(f=f)['status'], 'REFUSED')

    def test_03_concurrent_writers(self):
        results=[self.collect(p) for p in [self.spawn() for _ in range(4)]]
        self.assertEqual([r['status'] for r in results].count('COMMITTED'),1)
        self.assertEqual([r['status'] for r in results].count('ALREADY_COMMITTED'),3)
        self.expected_commits=1

    def test_04_crash_immediately_before_commit(self):
        self.collect(self.spawn('before_commit'),81)
        (self.root/'immediately-after-crash.json').write_text(json.dumps(self.rows(),indent=2))
        self.assertEqual(self.rows()['commitments'],[])
        self.assertEqual(json.loads(self.rows()['ledger'][0]['body'])['consumed_codes'],{})
        self.assertEqual(self.apply(self.adapter())['status'],'COMMITTED')
        self.expected_commits=1

    def test_05_crash_immediately_after_commit(self):
        self.collect(self.spawn('after_commit'),82)
        (self.root/'immediately-after-crash.json').write_text(json.dumps(self.rows(),indent=2))
        self.assertEqual(len(self.rows()['commitments']),1)
        self.assertEqual(self.apply(self.adapter())['status'],'ALREADY_COMMITTED')
        self.expected_commits=1

    def test_06_revocation_and_stale_worker(self):
        stale=self.adapter()
        self.revoke()
        self.assertEqual(self.apply(stale)['status'],'REFUSED')
        with self.assertRaises(ValueError):
            self.a.admit_owner(self.f['owner_authorization'],self.f['mandate'])

    def test_07_expiry_after_waiting_for_lock(self):
        # Clock is sampled only after BEGIN IMMEDIATE; waiting cannot freeze it.
        c=sqlite3.connect(self.path,isolation_level=None);c.execute('BEGIN IMMEDIATE')
        from concurrent.futures import ThreadPoolExecutor
        current=[NOW]
        a=self.adapter(clock=lambda:current[0])
        with ThreadPoolExecutor(1) as pool:
            future=pool.submit(self.apply,a)
            time.sleep(0.05)
            current[0]=NOW+timedelta(minutes=6)
            c.execute('COMMIT');c.close()
            self.assertEqual(future.result(timeout=15)['status'],'REFUSED')

    def test_08_stale_evidence_config_or_site(self):
        self.sql('UPDATE sites SET version=2')
        self.assertEqual(self.apply()['status'],'REFUSED')
        self.sql('UPDATE sites SET version=1')
        for field in ('simulation_digest','robot_config_digest'):
            original=self.f['site'][field]
            alternate=self.f['site']['robot_config_digest' if field=='simulation_digest' else 'simulation_digest']
            self.sql('UPDATE sites SET '+field+'=?',(alternate,))
            self.assertEqual(self.apply()['status'],'REFUSED',field)
            self.sql('UPDATE sites SET '+field+'=?',(original,))

    def test_09_current_receiver_policy(self):
        self.sql('UPDATE receiver SET enabled=0')
        self.assertEqual(self.apply()['status'],'REFUSED')
        self.sql('UPDATE receiver SET enabled=1,policy_hash=?',('00'*32,))
        self.assertEqual(self.apply()['status'],'REFUSED')

    def test_10_worker_succession_and_subject(self):
        self.assertEqual(self.apply(self.adapter(subject_source=lambda:'operator:mallory'))['status'],'REFUSED')
        # Claude/Codex are worker labels, not authenticated subject identities.
        self.assertEqual(self.collect(self.spawn())['status'],'COMMITTED')
        self.expected_commits=1
        self.assertEqual(self.apply(self.adapter())['status'],'ALREADY_COMMITTED')
        self.revoke()
        self.assertEqual(self.apply(self.adapter())['status'],'REFUSED')

    def test_11_new_receipt_same_transition_and_one_use_code(self):
        self.assertEqual(self.apply()['status'],'COMMITTED');self.expected_commits=1
        f=fixture(self.root,case='default',code='ed'*32)
        self.assertNotEqual(f['receipt']['payload_hash'],self.f['receipt']['payload_hash'])
        self.assertEqual(self.apply(f=f)['status'],'REFUSED')
        f=fixture(self.root,case='default',code=self.f['code'])
        self.assertEqual(self.apply(f=f)['status'],'REFUSED')

    def test_12_outcome_and_evidence_tampering(self):
        self.assertEqual(self.apply()['status'],'COMMITTED');self.expected_commits=1
        self.sql('UPDATE artifacts SET body=? WHERE digest=?',('{"approved":false}',self.f['site']['simulation_digest']))
        self.expected_verifier=False

    def test_13_missing_store_and_reinitialization(self):
        with self.assertRaises(FileExistsError):
            initialize(self.path,roots=self.f['roots'],site=self.f['site'],artifacts=self.f['artifacts'],policy_hash=self.f['policy_hash'],now=NOW)
        old=self.path;self.path=self.root/'missing.sqlite3'
        try:
            with self.assertRaises(sqlite3.OperationalError):self.adapter()
        finally:self.path=old

    def test_14_clock_rollback_and_mutable_input(self):
        self.assertEqual(self.apply(self.adapter(clock=lambda:NOW-timedelta(seconds=1)))['status'],'REFUSED')
        original=copy.deepcopy(self.f)
        def subject():
            self.f['action']['settings']['robot_config_digest']='00'*32
            return SUBJECT
        self.assertEqual(self.apply(self.adapter(subject_source=subject))['status'],'COMMITTED')
        self.expected_commits=1
        recorded=json.loads(self.rows()['commitments'][0]['action'])
        self.assertEqual(recorded,original['action'])

    def test_15_foreign_owner_principal_and_root_swap(self):
        roots=copy.deepcopy(self.f['roots']);roots['owner_id']='wrong'
        with self.assertRaises(ValueError):self.adapter(roots=roots)
        m=copy.deepcopy(self.f['mandate']);m['principal_id']='other-owner'
        auth=issue_mandate_authorization(slot_id=self.f['roots']['slot_id'],owner_id=self.f['roots']['owner_id'],
            mandate=m,state='ACTIVE',sequence=2,predecessor_hash=self.f['owner_authorization']['payload_hash'],
            issued_at=NOW,expires_at=NOW+timedelta(minutes=5),key=key('71'))
        with self.assertRaises(ValueError):self.a.admit_owner(auth,m)


class ConventionalTests(AtomicConsequenceTests):
    implementation='conventional'

# Additional falsifiers discovered during independent code review. They apply to
# both implementations; only the OpenLine-specific JSON ledger has a schema.
def late_expiry(self):
    current=[NOW]
    def subject():
        current[0]=NOW+timedelta(minutes=6)
        return SUBJECT
    a=self.adapter(clock=lambda:current[0],subject_source=subject)
    self.assertEqual(self.apply(a)['status'],'REFUSED')


def ledger_corruption(self):
    if self.implementation!='openline':
        self.skipTest('conventional consumption has no JSON-ledger state')
    state=json.loads(self.rows()['ledger'][0]['body']);state['schema']='invalid'
    self.sql('UPDATE ledger SET body=?',(canonical(state),))
    self.assertEqual(self.apply()['status'],'REFUSED')
    # Preserve raw invalid state snapshot; restore only to allow independent
    # verifier to establish the zero-consequence tuple for this local scenario.
    (self.root/'corrupt-ledger.json').write_text(canonical(state))
    state['schema']='openline.proof_to_policy.commit-ledger.v1.1'
    self.sql('UPDATE ledger SET body=?',(canonical(state),))


def uniqueness_constraints(self):
    self.assertEqual(self.apply()['status'],'COMMITTED');self.expected_commits=1
    row=self.rows()['commitments'][0]
    for field in ('decision_hash','authorization_hash','code_hash','idempotency_key'):
        clone=dict(row);clone.update(seq=2,idempotency_key='other',decision_hash='01'*32,
          authorization_hash='02'*32,code_hash='03'*32,before_version=2,after_version=3)
        clone[field]=row[field]
        with self.assertRaises(sqlite3.IntegrityError):
            with sqlite3.connect(self.path) as c:
                c.execute('INSERT INTO commitments VALUES ('+','.join('?' for _ in clone)+')',tuple(clone.values()))


def revocation_waiter(self):
    rev=issue_mandate_authorization(slot_id=self.f['roots']['slot_id'],owner_id=self.f['roots']['owner_id'],
        mandate=self.f['mandate'],state='REVOKED',sequence=2,predecessor_hash=self.f['owner_authorization']['payload_hash'],
        issued_at=NOW,expires_at=NOW+timedelta(minutes=5),key=key('71'))
    with sqlite3.connect(self.path) as c:
        c.execute('BEGIN IMMEDIATE')
        # Exact signed admin transition, held uncommitted while writer starts.
        c.execute('INSERT INTO owner_history VALUES (?,?,?,?)',(2,rev['payload_hash'],canonical(rev),canonical(self.f['mandate'])))
        p=self.spawn()
        time.sleep(0.05)
        c.commit()
    self.assertEqual(self.collect(p)['status'],'REFUSED')


def durable_state_disagreement(self):
    self.assertEqual(self.apply()['status'],'COMMITTED');self.expected_commits=1
    self.sql('UPDATE sites SET version=9')
    self.expected_verifier=False


for cls in (AtomicConsequenceTests, ConventionalTests):
    cls.test_16_expiry_during_authentication=late_expiry
    cls.test_17_ledger_schema_fail_closed=ledger_corruption
    cls.test_18_database_uniqueness_constraints=uniqueness_constraints
    cls.test_19_revocation_serializes_waiting_writer=revocation_waiter
    cls.test_20_independent_verifier_detects_state_disagreement=durable_state_disagreement

del cls  # avoid unittest collecting the loop alias as another test class


def tampered_ledger_verifier(self):
    self.assertEqual(self.apply()['status'],'COMMITTED');self.expected_commits=1
    target=self.root/'tampered-ledger.sqlite3'
    with sqlite3.connect(self.path) as source, sqlite3.connect(target) as dest:
        source.backup(dest)
    from olp_gate.verified_commit import VerifiedCommitLedger
    ledger=VerifiedCommitLedger._empty()
    if self.implementation=='conventional':ledger['consumed_codes']={'00'*32:{}}
    with sqlite3.connect(target) as c:c.execute('UPDATE ledger SET body=?',(canonical(ledger),))
    r=subprocess.run([sys.executable,str(HERE/'verify.py'),str(target),'--roots',str(self.root/'roots.json')],text=True,capture_output=True)
    (self.root/'tampered-ledger-verifier.json').write_text(r.stdout)
    self.assertEqual(r.returncode,1,r.stdout+r.stderr)

AtomicConsequenceTests.test_21_independent_verifier_detects_consumption_tampering=tampered_ledger_verifier
ConventionalTests.test_21_independent_verifier_detects_consumption_tampering=tampered_ledger_verifier
