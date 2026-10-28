export function trimEvents(events,oldest,limit){
  let low=0,high=events.length;
  while(low<high){
    const middle=(low+high)>>>1;
    if(events[middle].sequence<oldest)low=middle+1;else high=middle;
  }
  const removed=Math.max(low,events.length-limit);
  if(removed>0)events.splice(0,removed);
  return removed>0;
}

export function mergeEvents(events,incoming,cursor,oldest,limit){
  const fresh=incoming.filter(event=>event.sequence>cursor&&event.sequence>=oldest);
  for(const event of fresh)events.push(event);
  return trimEvents(events,oldest,limit)||fresh.length>0;
}
