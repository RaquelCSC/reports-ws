from dataclasses import dataclass
from datetime import datetime


@dataclass
class Visitor:
    id: str


@dataclass
class Product:
    id: int
    name: str
    activity_type: str


@dataclass
class Sell:
    id: int
    visitor_id: str
    product_id: int
    date: datetime
    value: int


@dataclass
class VisitorVisit:
    id: int
    date: datetime
    duration_secs: int
    is_new: bool
    host: str
    visitor_id: str


@dataclass
class ProductVisit:
    id: int
    date: datetime
    product_id: int
