import test from "node:test";
import assert from "node:assert/strict";
import {compileFilter,parseFilterInput,normalizeFilterValue,formatFilterValue} from "../trafficlog/web/filters.mjs";

const event={source:"10.0.5.100",destination:"10.0.1.24",source_port:51000,destination_port:445,action:"reject",protocol:"TCP",rule_name:"Block cameras: SMB",input:"Camera VLAN",output:"LAN",chain:"forward"};

test("field labels and short aliases resolve to the same filter",()=>{
  assert.deepEqual(parseFilterInput("Source IP: 10.0.5.0/24"),{field:"source",value:"10.0.5.0/24"});
  assert.deepEqual(parseFilterInput("src_ip: 10.0.5.100"),{field:"source",value:"10.0.5.100"});
  assert.deepEqual(parseFilterInput("Rule: Block cameras: SMB"),{field:"rule_name",value:"Block cameras: SMB"});
  assert.equal(parseFilterInput("unrecognized: text"),null);
});

test("actions use displayed labels and match exact decisions",()=>{
  assert.equal(normalizeFilterValue("action","Blocked, Rejected"),"drop,reject");
  assert.equal(formatFilterValue("action","drop,reject"),"Blocked, Rejected");
  assert.equal(compileFilter("action","Rejected")(event),true);
  assert.equal(compileFilter("action","Blocked")(event),false);
  assert.throws(()=>compileFilter("action","anything"));
});

test("CIDR filters handle host, network and zero-length prefixes",()=>{
  assert.equal(compileFilter("source","10.0.5.0/24")(event),true);
  assert.equal(compileFilter("source","10.0.4.0/24")(event),false);
  assert.equal(compileFilter("source","0.0.0.0/0")(event),true);
  assert.equal(compileFilter("source","10.0.5.100/32")(event),true);
  assert.throws(()=>compileFilter("source","10.0.5.300"));
  assert.throws(()=>compileFilter("source","10.0.5.0/33"));
});

test("port lists and ranges exclude absent or out-of-range ports",()=>{
  const match=compileFilter("destination_port","80,443-445");
  assert.equal(match(event),true);
  assert.equal(match({...event,destination_port:446}),false);
  assert.equal(match({...event,destination_port:null}),false);
  assert.throws(()=>compileFilter("destination_port","65536"));
});

test("protocol matching is case insensitive and exact",()=>{
  const match=compileFilter("protocol","tcp,udp");
  assert.equal(match(event),true);
  assert.equal(match({...event,protocol:"ICMP"}),false);
  assert.equal(match({...event,protocol:"TCP-other"}),false);
});

test("structured filters and free text combine with AND",()=>{
  const filters=[compileFilter("action","Rejected"),compileFilter("source","10.0.5.0/24"),compileFilter("text","cameras: smb")];
  assert.equal(filters.every(match=>match(event)),true);
  assert.equal(filters.every(match=>match({...event,action:"accept"})),false);
  assert.equal(compileFilter("input","camera vlan")(event),true);
});
