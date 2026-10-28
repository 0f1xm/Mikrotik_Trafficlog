import test from "node:test";
import assert from "node:assert/strict";
import {compileFilter,parseFilterInput,normalizeFilterValue,formatFilterValue,formatFilterOperator} from "../trafficlog/web/filters.mjs";

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

test("inequality and NOT syntax preserve values and resolve aliases",()=>{
  for(const query of ["Protocol != TCP","Protocol ≠ TCP","!Protocol: TCP","NOT Protocol: TCP"]){
    assert.deepEqual(parseFilterInput(query),{field:"protocol",value:"TCP",negated:true});
  }
  assert.deepEqual(parseFilterInput("src_ip != 10.0.5.0/24"),{field:"source",value:"10.0.5.0/24",negated:true});
  assert.deepEqual(parseFilterInput("Protocol = TCP"),{field:"protocol",value:"TCP"});
  assert.deepEqual(parseFilterInput("Rule: !important"),{field:"rule_name",value:"!important"});
});

test("negation excludes a complete protocol or action list",()=>{
  assert.equal(compileFilter("protocol","tcp,udp",true)(event),false);
  assert.equal(compileFilter("protocol","tcp,udp",true)({...event,protocol:"ICMP"}),true);
  assert.equal(compileFilter("action","Blocked, Rejected",true)(event),false);
  assert.equal(compileFilter("action","Blocked, Rejected",true)({...event,action:"accept"}),true);
});

test("negated networks exclude all listed networks",()=>{
  const match=compileFilter("source","10.0.5.0/24,192.168.0.0/16",true);
  assert.equal(match(event),false);
  assert.equal(match({...event,source:"192.168.3.4"}),false);
  assert.equal(match({...event,source:"172.16.0.1"}),true);
  assert.equal(compileFilter("source","0.0.0.0/0",true)(event),false);
});

test("negated port ranges retain events without the excluded port",()=>{
  const match=compileFilter("destination_port","80,443-445",true);
  assert.equal(match(event),false);
  assert.equal(match({...event,destination_port:53}),true);
  assert.equal(match({...event,destination_port:null}),true);
});

test("negated free text and interfaces invert their match",()=>{
  assert.equal(compileFilter("text","cameras: smb",true)(event),false);
  assert.equal(compileFilter("text","management",true)(event),true);
  assert.equal(compileFilter("input","Camera VLAN",true)(event),false);
});

test("positive and negated filters keep AND semantics",()=>{
  const filters=[compileFilter("source","10.0.5.0/24"),compileFilter("protocol","UDP",true)];
  assert.equal(filters.every(match=>match(event)),true);
  assert.equal(filters.every(match=>match({...event,protocol:"UDP"})),false);
  assert.equal(filters.every(match=>match({...event,source:"10.0.4.10"})),false);
  assert.equal([compileFilter("protocol","TCP"),compileFilter("protocol","TCP",true)].every(match=>match(event)),false);
});

test("negation still rejects invalid filter values",()=>{
  assert.throws(()=>compileFilter("source","10.0.5.300",true));
  assert.throws(()=>compileFilter("destination_port","70000",true));
  assert.throws(()=>compileFilter("action","invalid",true));
});

test("membership syntax supports networks and incomplete value suggestions",()=>{
  assert.deepEqual(parseFilterInput("Source IP in 10.0.1.0/24"),{field:"source",value:"10.0.1.0/24"});
  assert.deepEqual(parseFilterInput("src not in 10.0.1.0/24"),{field:"source",value:"10.0.1.0/24",negated:true});
  assert.deepEqual(parseFilterInput("Destination port NOT IN 80,443"),{field:"destination_port",value:"80,443",negated:true});
  assert.deepEqual(parseFilterInput("Ingress: Camera VLAN"),{field:"input",value:"Camera VLAN"});
  assert.deepEqual(parseFilterInput("Source IP not in "),{field:"source",value:"",negated:true});
  assert.deepEqual(parseFilterInput("Rule: Log not in LAN"),{field:"rule_name",value:"Log not in LAN"});
});

test("network, range and list chips use membership operators",()=>{
  for(const [field,value] of [["source","10.0.1.0/24"],["destination","0.0.0.0/0"],["destination_port","443-445"],["protocol","TCP,UDP"]]){
    assert.equal(formatFilterOperator(field,value),"in");
    assert.equal(formatFilterOperator(field,value,true),"not in");
    assert.deepEqual(parseFilterInput(`${field} not in ${value}`),{field,value,negated:true});
  }
  for(const [field,value] of [["source","10.0.1.1"],["action","drop"],["protocol","TCP"],["text","one,two"]]){
    assert.equal(formatFilterOperator(field,value),"=");
    assert.equal(formatFilterOperator(field,value,true),"≠");
  }
});
