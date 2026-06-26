from abc import ABC, abstractmethod


class DebugEngine(ABC):

    @abstractmethod
    def execute(self, command: str) -> str:
        ...

    @abstractmethod
    def connect(self) -> None:
        ...

    @abstractmethod
    def disconnect(self) -> None:
        ...

    @property
    @abstractmethod
    def connected(self) -> bool:
        ...

    @property
    @abstractmethod
    def target_running(self) -> bool:
        ...
