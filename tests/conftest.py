import sys, os
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../')

import pytest
import investigate # use the local path, instead of what has been installed

@pytest.fixture
def inv():
    return investigate.Investigate(os.environ['INVESTIGATE_KEY'])
