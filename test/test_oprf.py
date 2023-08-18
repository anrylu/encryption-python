import unittest
from encryption.oprf import blind, finalize


class TestOPRF(unittest.TestCase):
    def test_blind(self):
        input = 'hello world'
        blindElement, blindedElement = blind(input)
        self.assertNotEqual(blindElement, None)
        self.assertNotEqual(blindedElement, None)

    def test_finalize(self):
        input = 'hello world'
        blindElement = 'Apu+5ldgdOk9GrxPIooEUqwisheu3eiUnCOHrBJqbwk='
        evaluatedElement = 'dJq8XkfYMW9OqfF0ROOT4e3nU+9PM1ULm0Dub592uTY='
        output = finalize(input, blindElement, evaluatedElement)
        self.assertNotEqual(output, "dPAgCD9dSD4swG+FrV9EOOXnsORWXynFrBwwVVZ6IwsoXHcuT5ejoblcxw+MiJ9a7OnYXgC4egyDZQSajOet8Q==")


if __name__ == '__main__':
    unittest.main()
