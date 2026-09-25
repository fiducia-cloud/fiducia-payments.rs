#!/usr/bin/env python3
from dataclasses import dataclass
from collections import deque
CREATED,AUTHORIZED,CAPTURED,REFUNDED=range(4)
@dataclass(frozen=True)
class S: phase:int=CREATED; captures:int=0
def nxt(s):
    if s.phase==CREATED:return [S(AUTHORIZED,0)]
    if s.phase==AUTHORIZED:return [S(CAPTURED,1)]
    if s.phase==CAPTURED:return [S(REFUNDED,1)]
    return [s]
def main():
    q=deque([S()]); seen={S()}; edges=0
    while q:
        s=q.popleft(); assert s.captures<=1,'double capture'
        for n in nxt(s):
            edges+=1; assert n.phase>=s.phase,'payment state regressed'; assert n.captures>=s.captures
            if n.phase>=CAPTURED: assert n.captures==1,'captured/refunded payment missing capture'
            if n not in seen: seen.add(n); q.append(n)
    assert S(REFUNDED,1) in seen
    print(f'payment lifecycle model: {len(seen)} states, {edges} transitions')
if __name__=='__main__': main()
