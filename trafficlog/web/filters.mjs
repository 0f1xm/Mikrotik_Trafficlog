export const actions = {accept:"Allowed",drop:"Blocked",reject:"Rejected"};
export const fields = {source:"Source IP",destination:"Destination IP",destination_port:"Destination port",source_port:"Source port",action:"Action",protocol:"Protocol",rule_name:"Rule",input:"Ingress",output:"Egress",chain:"Chain",text:"Search"};
const actionAliases={allowed:"accept",allow:"accept",accept:"accept",blocked:"drop",block:"drop",deny:"drop",drop:"drop",rejected:"reject",reject:"reject"};
const aliases={src:"source",src_ip:"source",source:"source",dst:"destination",dst_ip:"destination",destination:"destination",dst_port:"destination_port",dport:"destination_port",src_port:"source_port",sport:"source_port",rule:"rule_name",in:"input",out:"output",search:"text"};
for(const [key,label] of Object.entries(fields)){aliases[key]=key;aliases[label.toLowerCase()]=key;}

export function parseFilterInput(input){
  const match=input.match(/^([^:]+):\s*([\s\S]*)$/);
  if(!match)return null;
  const field=aliases[match[1].trim().toLowerCase()];
  return field?{field,value:match[2].trim()}:null;
}

export function normalizeFilterValue(field,value){
  value=String(value).trim();
  if(!value)throw new Error("Enter a filter value.");
  if(field==="text")return value;
  const values=value.split(",").map(v=>v.trim()).filter(Boolean);
  if(!values.length)throw new Error("Enter a filter value.");
  if(field==="action")return values.map(v=>{
    const action=actionAliases[v.toLowerCase()];
    if(!action)throw new Error("Choose Allowed, Blocked or Rejected.");
    return action;
  }).join(",");
  if(field==="protocol")return values.map(v=>v.toUpperCase()).join(",");
  return value;
}

export function formatFilterValue(field,value){
  return field==="action"?value.split(",").map(v=>actions[v]||v).join(", "):value;
}

export function ipNumber(ip){
  const parts=ip.split(".");
  if(parts.length!==4||parts.some(p=>!/^\d{1,3}$/.test(p)||Number(p)>255))throw new Error("Enter a valid IPv4 address or CIDR network.");
  return parts.reduce((n,p)=>(n*256+Number(p))>>>0,0);
}

export function eventSearchText(event){
  return [event.source,event.destination,event.source_port,event.destination_port,event.rule_name,event.rule_id,event.protocol,event.input,event.output,event.chain,event.state,event.source_mac,actions[event.action],event.action].join(" ").toLowerCase();
}

export function compileFilter(field,value){
  value=normalizeFilterValue(field,value);
  if(field==="text")return e=>eventSearchText(e).includes(value.toLowerCase());
  const values=value.split(",").map(v=>v.trim()).filter(Boolean);
  if(field==="source"||field==="destination"){
    const nets=values.map(v=>{
      const parts=v.split("/");
      if(parts.length>2||(parts.length===2&&!/^\d+$/.test(parts[1])))throw new Error("Invalid IPv4 network.");
      const bits=parts.length===2?Number(parts[1]):32;
      if(bits<0||bits>32)throw new Error("Prefix length must be between /0 and /32.");
      const mask=bits===0?0:(0xffffffff<<(32-bits))>>>0;
      return {network:(ipNumber(parts[0])&mask)>>>0,mask};
    });
    return e=>nets.some(n=>{try{return ((ipNumber(e[field])&n.mask)>>>0)===n.network;}catch{return false;}});
  }
  if(field.endsWith("_port")){
    const ranges=values.map(v=>{
      if(!/^\d+(?:-\d+)?$/.test(v))throw new Error("Enter a port, range or comma-separated list.");
      const [a,b]=v.split("-").map(Number),end=b??a;
      if(a<0||end>65535||end<a)throw new Error("Port range must be between 0 and 65535.");
      return [a,end];
    });
    return e=>e[field]!=null&&ranges.some(([a,b])=>Number(e[field])>=a&&Number(e[field])<=b);
  }
  if(field==="action"||field==="protocol")return e=>values.some(v=>String(e[field]).toLowerCase()===v.toLowerCase());
  return e=>values.some(v=>String(e[field]||"").toLowerCase().includes(v.toLowerCase()));
}
