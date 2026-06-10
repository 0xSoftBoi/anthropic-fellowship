```markdown
# anthropic-fellowship Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `anthropic-fellowship` Python repository. It covers file organization, import/export styles, commit message habits, and testing practices. By following these guidelines, contributors can maintain consistency and quality across the codebase.

## Coding Conventions

### File Naming
- Use **snake_case** for all Python files.
  - Example: `data_loader.py`, `model_utils.py`

### Import Style
- Prefer **relative imports** within the package.
  - Example:
    ```python
    from .utils import preprocess_data
    from ..models import ModelClass
    ```

### Export Style
- Use **named exports** by explicitly listing public objects in `__all__`.
  - Example:
    ```python
    __all__ = ["MyClass", "my_function"]
    ```

### Commit Messages
- No strict prefixes; messages are freeform and descriptive.
- Average length: ~64 characters.
  - Example:  
    ```
    Fix bug in data preprocessing for edge cases
    ```

## Workflows

### Adding a New Module
**Trigger:** When you need to add new functionality to the codebase  
**Command:** `/add-module`

1. Create a new Python file using snake_case (e.g., `new_feature.py`).
2. Implement your functionality.
3. Use relative imports to reference existing code.
4. Add your public classes/functions to `__all__` if needed.
5. Write corresponding tests in a `*.test.*` file.
6. Commit changes with a clear, descriptive message.

### Running Tests
**Trigger:** After making changes or before submitting a pull request  
**Command:** `/run-tests`

1. Locate test files matching the `*.test.*` pattern.
2. Run tests using the project's preferred method (framework unknown; try `pytest` or `unittest`).
   - Example:
     ```
     pytest
     ```
     or
     ```
     python -m unittest discover
     ```
3. Ensure all tests pass before pushing changes.

### Refactoring Existing Code
**Trigger:** When improving code readability or structure  
**Command:** `/refactor`

1. Update file and function names to follow snake_case if needed.
2. Replace absolute imports with relative imports.
3. Ensure all exports are named and listed in `__all__`.
4. Update or add tests as necessary.
5. Commit with a descriptive message about the refactor.

## Testing Patterns

- Test files follow the `*.test.*` naming convention (e.g., `utils.test.py`).
- Testing framework is not specified; try `pytest` or `unittest`.
- Place tests alongside or near the modules they test.
- Example test file:
  ```python
  # utils.test.py
  import unittest
  from .utils import preprocess_data

  class TestPreprocessData(unittest.TestCase):
      def test_basic(self):
          self.assertEqual(preprocess_data("input"), "expected_output")
  ```

## Commands
| Command        | Purpose                                      |
|----------------|----------------------------------------------|
| /add-module    | Scaffold and add a new module                |
| /run-tests     | Run all tests in the repository              |
| /refactor      | Refactor code to follow repository patterns  |
```
