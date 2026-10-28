import test from "node:test";
import assert from "node:assert/strict";
import {mergeEvents,trimEvents} from "../trafficlog/web/events.mjs";

test("incremental batches retain more than ten thousand events without duplicates",()=>{
  const events=[];
  for(let start=1;start<=20000;start+=2000){
    mergeEvents(events,Array.from({length:2000},(_,i)=>({sequence:start+i})),start-1,1,1000000);
  }
  assert.equal(events.length,20000);
  assert.equal(mergeEvents(events,[{sequence:20000}],20000,1,1000000),false);
  assert.equal(events.length,20000);
});

test("browser retention follows backend evictions and the selected event limit",()=>{
  const events=Array.from({length:20000},(_,i)=>({sequence:i+1}));
  const paused=[...events];
  assert.equal(trimEvents(events,5000,15000),true);
  assert.equal(events.length,15000);
  assert.equal(events[0].sequence,5001);
  assert.equal(trimEvents(paused,5001,15000),true);
  assert.equal(paused.length,events.length);
  assert.equal(mergeEvents(events,[{sequence:19999},{sequence:20001}],20000,10000,15000),true);
  assert.equal(events[0].sequence,10000);
  assert.equal(events.at(-1).sequence,20001);
  assert.equal(trimEvents(events,30000,15000),true);
  assert.equal(events.length,0);
});
