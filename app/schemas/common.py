from pydantic import BaseModel, ConfigDict
from typing import List, Optional

class RuleBase(BaseModel):
    id: int # РќР°С€ ID
    ext_id: str # NGFW ID
    name: str
    real_priority_index: int
    action: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class FolderCreate(BaseModel):
    name: str

class FolderResponse(BaseModel):
    id: int
    name: str
    rules: List[RuleBase]

    model_config = ConfigDict(from_attributes=True)

class MoveRuleRequest(BaseModel):
    rule_ext_id: str
    target_ext_id: str
    position: str = "after" # or 'before'
