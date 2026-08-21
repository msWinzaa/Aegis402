from dataclasses import dataclass
@dataclass
class ExecutionPolicy:
    max_cost_units:int=100_000

def check_execution_cost(estimated_cost,policy):
    try: estimated_cost=int(estimated_cost)
    except (TypeError,ValueError): return False,'invalid execution cost'
    if estimated_cost<0:return False,'negative execution cost'
    if estimated_cost>policy.max_cost_units:return False,'execution cost exceeds policy'
    return True,'execution cost passed'
