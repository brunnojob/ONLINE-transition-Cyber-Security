const form = document.querySelector('#demo-form');
const run = document.querySelector('#run');
const error = document.querySelector('#error');
const status = document.querySelector('#status');
const titles = {valid:'Autorização aceita.',amount:'Um centavo. Bloqueado.',recipient:'Outro destinatário. Bloqueado.',replay:'A assinatura não vale duas vezes.',expired:'O prazo faz parte da autorização.',concurrent:'Oito tentativas. Uma instrução.'};
const descriptions = {valid:'A assinatura corresponde aos dados originais. Uma instrução foi enfileirada.',amount:'A mensagem assinada contém um centavo a mais que o desafio original. A verificação falha.',recipient:'A assinatura foi gerada para um destinatário diferente do desafio original.',replay:'Após o primeiro despacho, reutilizar a assinatura para reautorizar a operação é rejeitado.',expired:'O relógio de teste avançou 121 segundos. O prazo do desafio já terminou.',concurrent:'Oito chamadas concorrentes executaram o motor. Só uma conseguiu inserir a instrução na fila.'};
let report;
function show(id,value){document.querySelector(id).textContent=value;}
form.addEventListener('submit',async event=>{
  event.preventDefault(); error.textContent='';
  const input = document.querySelector('#amount').value.trim();
  if(!/^\d{1,6}([.,]\d{1,2})?$/.test(input)){error.textContent='Informe um valor entre R$ 0,01 e R$ 999.999,99, sem separador de milhar.';return;}
  const [whole,fraction=''] = input.replace(',','.').split('.');
  const amount = Number(whole)*100+Number(fraction.padEnd(2,'0'));
  if(amount<1 || amount>99999999){error.textContent='O valor deve estar entre R$ 0,01 e R$ 999.999,99.';return;}
  run.disabled=true; status.textContent='EXECUTANDO PYTHON…'; report=undefined;
  document.querySelector('#download').hidden=true;
  try{
    const response=await fetch('/api/demo',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scenario:new FormData(form).get('scenario'),amount_minor:amount,recipient:document.querySelector('#recipient').value.trim()}),signal:AbortSignal.timeout(30000)});
    const result=await response.json();
    if(!response.ok || !result.passed)throw new Error(result.error || 'O cenário não produziu o resultado esperado.');
    report=result;
    show('#result-title',titles[result.scenario]);show('#result-description',descriptions[result.scenario]);
    show('#state',result.state);show('#dispatches',String(result.dispatches));show('#elapsed',result.elapsed_ms+' ms');
    const steps=document.querySelector('#steps');steps.replaceChildren();
    for(const step of result.steps){const li=document.createElement('li');const title=document.createElement('b');title.textContent=step.action+' → '+step.outcome;const detail=document.createElement('p');detail.textContent=step.detail;li.append(title,detail);steps.append(li);}
    show('#audit',JSON.stringify(result.audit,null,2));show('#payload',result.signed_payload+'\n\nSHA-256 DO DESAFIO ORIGINAL\n'+result.original_payload_sha256);
    document.querySelector('#audit-panel').hidden=false;document.querySelector('#payload-panel').hidden=false;document.querySelector('#download').hidden=false;
    status.textContent='RESULTADO VERIFICADO';
  }catch(cause){status.textContent='TESTE NÃO CONCLUÍDO';error.textContent='Não foi possível concluir a execução. '+(cause.name==='TimeoutError'?'O servidor demorou a responder. Tente novamente.':cause.message);show('#result-title','Execução indisponível.');show('#result-description','O resultado anterior não representa esta tentativa. Tente novamente.');show('#state','—');show('#dispatches','—');show('#elapsed','—');document.querySelector('#steps').replaceChildren();document.querySelector('#audit-panel').hidden=true;document.querySelector('#payload-panel').hidden=true;
  }finally{run.disabled=false;}
});
document.querySelector('#download').addEventListener('click',()=>{if(!report)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));const link=document.createElement('a');link.href=url;link.download='transaction-guard-'+report.scenario+'.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
