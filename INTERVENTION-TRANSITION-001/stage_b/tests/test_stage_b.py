import csv, json, tempfile, unittest
from pathlib import Path
import numpy as np

from transition_benchmark.data import load_cells
from transition_benchmark.model import build_outcome_index, predict_one


class StageBTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(__file__).parents[1]
        self.lock=json.loads((self.root/'config/stage_b.frozen.json').read_text())

    def test_split_is_disjoint_and_complete(self):
        s=self.lock['split']
        tr,va,ho=set(s['train']),set(s['validation']),set(s['holdout'])
        self.assertEqual(len(tr),30); self.assertEqual(len(va),10); self.assertEqual(len(ho),10)
        self.assertFalse(tr&va); self.assertFalse(tr&ho); self.assertFalse(va&ho)
        self.assertEqual(tr|va|ho,{f'g1-{i:03d}' for i in range(50)})

    def test_holdout_label_barrier_ignores_invalid_holdout_label(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'cells.csv'
            with p.open('w',newline='') as f:
                w=csv.DictWriter(f,fieldnames=['context_id','action_id','lag','outcome_success'])
                w.writeheader(); w.writerow({'context_id':'train','action_id':'A','lag':0,'outcome_success':1})
                w.writerow({'context_id':'hold','action_id':'A','lag':0,'outcome_success':'SECRET'})
            rows=load_cells(p,{'train'})
            self.assertEqual(rows[0]['y_fail'],0)
            self.assertIsNone(rows[1]['y_fail'])

    def test_direct_conditioning_can_distinguish_remedies(self):
        rows=[]
        for cid,vals in {'c1':{('A',0):0,('B',0):1},'c2':{('A',0):0,('B',0):1},'c3':{('A',0):1,('B',0):0}}.items():
            for (a,l),y_fail in vals.items():
                rows.append({'context_id':cid,'action_id':a,'lag':l,'y_fail':y_fail})
        idx=build_outcome_index(rows,{'c1','c2','c3'})
        train_z=np.array([[0.0],[0.2],[4.0]])
        p_a=predict_one('direct_action_lag',np.array([0.1]),'A',0,train_z,['c1','c2','c3'],idx,2)
        p_b=predict_one('direct_action_lag',np.array([0.1]),'B',0,train_z,['c1','c2','c3'],idx,2)
        self.assertLess(p_a,0.1)
        self.assertGreater(p_b,0.9)

    def test_no_terrynce_scalar_model(self):
        code='\n'.join(p.read_text() for p in (self.root/'src/transition_benchmark').glob('*.py')).lower()
        self.assertNotIn('recoverability margin',code)
        self.assertNotIn('terrynce curve',code)

    def test_falsifiers_are_frozen(self):
        f=self.lock['primary_falsifiers']
        self.assertIn('95% lower bound > 0',f['action_conditioning_redundancy'])
        self.assertIn('95% lower bound > 0',f['lag_conditioning_redundancy'])
        self.assertEqual(self.lock['bootstrap']['replicates'],10000)
        self.assertEqual(self.lock['model']['feasible_threshold'],0.95)

if __name__=='__main__': unittest.main()
