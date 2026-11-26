#!/usr/bin/env python3
"""Compare separately resolved coordinate and formal-shadow query observations."""
import copy
import check

def validate(stage,expected,baseline,witness,mutant):
    full=copy.deepcopy(expected)
    negatives=[row for row in full['rows'] if row['path']==check.NEG]
    check.require(len(negatives)==1 and negatives[0]['expected_rows']==0,'formal-shadow oracle differs')
    negatives[0]['expected_rows']=1
    check.validate_query(stage,baseline,expected)
    check.validate_query(stage,witness,full)
    check.validate_query(stage,mutant,full)
    def identities(value):
        result={}
        for entity,_ in check.tuples(value):
            u=entity['url'];key=(check.file_uri(u['uri'],stage),*(u[k] for k in ('startLine','startColumn','endLine','endColumn')))
            check.require(key not in result,'duplicate control node');result[key]=entity['id']
        return result
    b=identities(baseline);w=identities(witness);m=identities(mutant)
    check.require(all(w.get(k)==v and m.get(k)==v for k,v in b.items()),'baseline node IDs differ in controls')
    check.require(w==m,'witness and mutant node IDs differ')
    return {'baseline_rows':14,'coordinate_witness_rows':15,'mutant_rows':15,'near_miss_added':1,'boundary':'Consistency of selected extracted AST nodes; no runtime or security claim.'}
