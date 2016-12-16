import os

import pytest
import investigate # use the local path, instead of what has been installed

@pytest.fixture
def inv():
    return investigate.Investigate(os.environ['INVESTIGATE_KEY'])
