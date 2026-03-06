from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel
from typing import Dict
import uuid
from app.models.state import RemediationState
from app.graph.workflow import app as workflow_app
from app.services.logger import get_logger

router = APIRouter()

# In-memory store for workflow states (for MVP)
# In production, use Redis or a database
workflow_store: Dict[str, RemediationState] = {}

class RemediationRequest(BaseModel):
    code_path: str
    vulnerability_type: str

def run_workflow(workflow_id: str, initial_state: RemediationState):
    logger = get_logger(workflow_id)
    logger.log_event("Orchestrator", "Workflow Started", initial_state.dict())
    
    # Run the graph
    # LangGraph's .invoke returns the final state
    try:
        final_state_dict = workflow_app.invoke(initial_state)
        # Convert back to Pydantic model
        # Note: LangGraph might return a dict or object depending on config.
        # Assuming dict for now as that's typical with StateGraph
        final_state = RemediationState(**final_state_dict)
        workflow_store[workflow_id] = final_state
        logger.log_event("Orchestrator", "Workflow Completed", final_state.dict())
    except Exception as e:
        logger.log_event("Orchestrator", "Workflow Failed", {"error": str(e)})
        # Store state with error info if possible, or just log
        pass

@router.post("/remediate", response_model=Dict[str, str])
async def start_remediation(request: RemediationRequest, background_tasks: BackgroundTasks):
    workflow_id = str(uuid.uuid4())
    
    initial_state = RemediationState(
        workflow_id=workflow_id,
        code_path=request.code_path,
        vulnerability_type=request.vulnerability_type,
        iteration_count=0
    )
    
    workflow_store[workflow_id] = initial_state
    
    background_tasks.add_task(run_workflow, workflow_id, initial_state)
    
    return {"workflow_id": workflow_id, "status": "started"}

@router.get("/status/{workflow_id}")
async def get_status(workflow_id: str):
    if workflow_id not in workflow_store:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    state = workflow_store[workflow_id]
    logger = get_logger(workflow_id)
    logs = logger.get_logs()
    
    return {
        "state": state.dict(),
        "logs": logs
    }
@router.post("/apply_patch/{workflow_id}")
async def apply_patch(workflow_id: str):
    if workflow_id not in workflow_store:
        raise HTTPException(status_code=404, detail="Workflow not found")
    
    state = workflow_store[workflow_id]
    
    if not state.patch_diff:
        raise HTTPException(status_code=400, detail="No patch available to apply")
        
    try:
        # In a real scenario, we might use a sandbox service here.
        # Since patch_diff currently stores the FULL verified code:
        with open(state.code_path, "w") as f:
            f.write(state.patch_diff)
            
        return {"status": "success", "message": "Patch applied successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
