"""Synthetic request and actual response contract against pinned official schemas."""
import copy
import json
from pathlib import Path
import unittest
import jsonschema

FIXTURES = Path(__file__).parent / "fixtures"


class OfficialSchemaTests(unittest.TestCase):
    def setUp(self):
        self.source = json.loads((FIXTURES / "lithic-asa-schemas.json").read_text())
        self.request = json.loads((FIXTURES / "official-asa-request.json").read_text())

    def validator(self, name):
        schema = {**self.source[name], "components": self.source["components"]}
        return jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())

    def test_complete_independent_request_is_official_shape(self):
        self.validator("request_schema").validate(self.request)
        old_shape = copy.deepcopy(self.request)
        old_shape["card_token"] = old_shape.pop("card")["token"]
        with self.assertRaises(jsonschema.ValidationError):
            self.validator("request_schema").validate(old_shape)

    def test_all_adapter_responses_are_documented_minimal_asa_values(self):
        validator = self.validator("response_schema")
        for result in ("APPROVED", "CARD_PAUSED", "UNAUTHORIZED_MERCHANT", "SUSPECTED_FRAUD"):
            validator.validate({"result": result})
            validator.validate({"result": result, "token": self.request["token"]})
        with self.assertRaises(jsonschema.ValidationError):
            validator.validate({"approved": True, "openline_receipt": {}})


if __name__ == "__main__":
    unittest.main(verbosity=2)
