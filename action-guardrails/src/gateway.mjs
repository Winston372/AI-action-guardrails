import {evaluateToolCall} from './policy.mjs';

/**
 * Generic integration for non-OpenClaw JS agents.
 * Keep the raw adapter private: expose only dispatch() to an untrusted agent.
 * `operatorApproval` must be implemented in a trusted, user-authenticated UI.
 */
export class GuardedDispatcher {
  constructor({policy, executeTool, operatorApproval}={}) {
    if(typeof executeTool!=='function')throw new TypeError('executeTool must be a function');
    this.policy=policy ?? {};
    this.executeTool=executeTool;
    this.operatorApproval=operatorApproval;
  }
  async dispatch(event) {
    const decision=evaluateToolCall(event,this.policy);
    if(decision.effect==='deny')return {executed:false,decision};
    if(decision.effect==='approve') {
      // Fail closed if there is no separately authenticated operator approval.
      if(typeof this.operatorApproval!=='function')return {executed:false,decision:{effect:'deny',code:'APPROVAL_UNAVAILABLE',reason:'No trusted approver configured'}};
      let accepted=false;
      try {accepted=(await this.operatorApproval(event,decision))===true;} catch{accepted=false;}
      if(!accepted)return {executed:false,decision:{effect:'deny',code:'APPROVAL_DENIED',reason:'Operator approval was not granted'}};
    }
    const result=await this.executeTool(event);
    return {executed:true,decision,result};
  }
}
