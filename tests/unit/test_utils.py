"""Module to test the utils.py file."""
from unittest import TestCase
from unittest.mock import patch, MagicMock

from kytos.core.interface import Interface
from kytos.lib.helpers import get_controller_mock, get_link_mock
from napps.amlight.sdntrace_cp import utils


# pylint: disable=too-many-public-methods, duplicate-code, protected-access
class TestUtils(TestCase):
    """Test utils.py functions."""

    def test_convert_entries_vlan(self):
        """Verify convert entries with simple example with vlan."""

        eth = {"dl_vlan": 100}
        dpid = {"dpid": "00:00:00:00:00:00:00:01", "in_port": 1}
        switch = {"switch": dpid, "eth": eth}
        entries = {"trace": switch}

        result = utils.convert_entries(entries)

        self.assertEqual(
            result,
            {
                "dpid": "00:00:00:00:00:00:00:01",
                "in_port": 1,
                "vlan_vid": [100],
            },
        )

    def test_convert_entries_translation(self):
        """Verify convert entries with all translations."""

        eth = {
            "dl_src": "A",
            "dl_dst": "B",
            "dl_type": "C",
            "dl_vlan": "D",
            "nw_src": "E",
            "nw_dst": "F",
            "nw_tos": "G",
            "nw_proto": "H",
        }
        dpid = {"dpid": "00:00:00:00:00:00:00:01", "in_port": 1}
        switch = {"switch": dpid, "eth": eth}
        entries = {"trace": switch}

        result = utils.convert_entries(entries)

        self.assertEqual(
            result,
            {
                "dpid": "00:00:00:00:00:00:00:01",
                "in_port": 1,
                "eth_src": "A",
                "eth_dst": "B",
                "eth_type": "C",
                "vlan_vid": ["D"],
                "ip4_src": "E",
                "ip4_dst": "F",
                "ip_tos": "G",
                "ip_proto": "H",
            },
        )

    def test_prepare_json(self):
        """Verify prepare json with simple tracepath result."""
        trace_result = []
        trace_step = {
            "in": {
                "dpid": "00:00:00:00:00:00:00:01",
                "port": 1,
                "time": "2022-06-01 01:01:01.100000",
                "type": "starting",
            }
        }
        trace_result.append(trace_step)

        trace_step = {
            "in": {
                "dpid": "00:00:00:00:00:00:00:03",
                "port": 3,
                "time": "2022-06-01 01:01:01.100000",
                "type": "trace",
                "vlan": 100,
            }
        }
        trace_result.append(trace_step)

        result = utils.prepare_json(trace_result)

        self.assertEqual(
            result,
            {
                "result": [
                    {
                        "dpid": "00:00:00:00:00:00:00:01",
                        "port": 1,
                        "time": "2022-06-01 01:01:01.100000",
                        "type": "starting",
                    },
                    {
                        "dpid": "00:00:00:00:00:00:00:03",
                        "port": 3,
                        "time": "2022-06-01 01:01:01.100000",
                        "type": "trace",
                        "vlan": 100,
                    },
                ]
            },
        )

    def test_prepare_json_empty(self):
        """Verify prepare json with empty result."""
        trace_result = []

        result = utils.prepare_json(trace_result)

        self.assertEqual(result, {"result": []})

    def test_format_result(self):
        """Verify format resul with simple tracepath result."""
        trace_result = []
        trace_step = {
            "in": {
                "dpid": "00:00:00:00:00:00:00:01",
                "port": 1,
                "time": "2022-06-02 02:02:02.200000",
                "type": "starting",
            }
        }
        trace_result.append(trace_step)

        trace_step = {
            "in": {
                "dpid": "00:00:00:00:00:00:00:03",
                "port": 3,
                "time": "2022-06-02 02:02:02.200000",
                "type": "trace",
                "vlan": 100,
            },
            "out": {"port": 2, "vlan": 200},
        }
        trace_result.append(trace_step)

        formatted = utils.format_result(trace_result)

        self.assertEqual(
            formatted,
            [
                {"dpid": "00:00:00:00:00:00:00:01", "in_port": 1},
                {
                    "dpid": "00:00:00:00:00:00:00:03",
                    "in_port": 3,
                    "out_port": 2,
                    "out_vlan": 200,
                    "in_vlan": 100,
                },
            ],
        )

    def test_compare_endpoints1(self):
        """Test for compare endpoinst for the first internal conditional."""
        endpoint1 = {
            "dpid": "00:00:00:00:00:00:00:01",
        }
        endpoint2 = {
            "dpid": "00:00:00:00:00:00:00:02",
        }

        # Test endpoint1 dpid != endpoint2 dpid
        result = utils._compare_endpoints(endpoint1, endpoint2)
        self.assertFalse(result)

    def test_compare_endpoints2(self):
        """Test for compare endpoinst for the second internal conditional."""
        endpoint1 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "out_port": 2,
            "out_vlan": 200,
        }
        endpoint2 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "in_port": 3,
            "in_vlan": 100,
        }

        # Test endpoint1 without in_port
        result = utils._compare_endpoints(endpoint1, endpoint2)
        self.assertFalse(result)

        endpoint1 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "in_port": 3,
            "in_vlan": 100,
        }
        endpoint2 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "in_port": 3,
            "in_vlan": 100,
        }

        # Test endpoint2 without out_port
        result = utils._compare_endpoints(endpoint1, endpoint2)
        self.assertFalse(result)

        endpoint1 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "in_port": 3,
            "in_vlan": 100,
        }
        endpoint2 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "out_port": 2,
            "out_vlan": 200,
        }

        # Test endpoint1 in_port != endpoint2 out_port
        result = utils._compare_endpoints(endpoint1, endpoint2)
        self.assertFalse(result)

    def test_compare_endpoints3(self):
        """Test for compare endpoinst for the third internal conditional."""
        endpoint1 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "in_port": 3,
            "out_port": 2,
            "in_vlan": 100,
        }
        endpoint2 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "in_port": 2,
            "out_port": 3,
            "out_vlan": 200,
        }

        # Test endpoint1 in_vlan != endpoint2 out_vlan
        result = utils._compare_endpoints(endpoint1, endpoint2)
        self.assertFalse(result)

    def test_compare_endpoints4(self):
        """Test for compare endpoinst for the first internal conditional."""
        endpoint1 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "in_port": 3,
            "out_port": 2,
            "in_vlan": 100,
        }
        endpoint2 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "in_port": 2,
            "out_port": 3,
        }

        # Test endpoint1 with in_vlan and endpoint2 without out_vlan
        result = utils._compare_endpoints(endpoint1, endpoint2)
        self.assertFalse(result)

        endpoint1 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "in_port": 3,
            "out_port": 2,
        }
        endpoint2 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "in_port": 2,
            "out_port": 3,
            "out_vlan": 200,
        }

        # Test endpoint1 without in_vlan and endpoint2 with out_vlan
        result = utils._compare_endpoints(endpoint1, endpoint2)
        self.assertFalse(result)

    def test_compare_endpoints5(self):
        """Test for compare endpoinst for the fifth internal conditional."""
        endpoint1 = {
            "dpid": "00:00:00:00:00:00:00:01",
            "in_port": 3,
            "out_port": 2,
            "out_vlan": 200,
        }
        endpoint2 = {
            "dpid": "00:00:00:00:00:00:00:01",
            "in_port": 2,
            "out_port": 3,
            "in_vlan": 100,
        }

        # Test endpoint1 out_vlan != endpoint2 in_vlan
        result = utils._compare_endpoints(endpoint1, endpoint2)
        self.assertFalse(result)

    def test_compare_endpoints6(self):
        """Test for compare endpoinst for the fifth internal conditional."""
        endpoint1 = {
            "dpid": "00:00:00:00:00:00:00:01",
            "in_port": 3,
            "out_port": 2,
            "out_vlan": 200,
        }
        endpoint2 = {
            "dpid": "00:00:00:00:00:00:00:01",
            "in_port": 2,
            "out_port": 3,
        }

        # Test endpoint1 with out_vlan and endpoint2 without in_vlan
        result = utils._compare_endpoints(endpoint1, endpoint2)
        self.assertFalse(result)

        endpoint1 = {
            "dpid": "00:00:00:00:00:00:00:01",
            "in_port": 3,
            "out_port": 2,
        }
        endpoint2 = {
            "dpid": "00:00:00:00:00:00:00:01",
            "in_port": 2,
            "out_port": 3,
            "in_vlan": 100,
        }

        # Test endpoint1 without out_vlan and endpoint2 with in_vlan
        result = utils._compare_endpoints(endpoint1, endpoint2)
        self.assertFalse(result)

    def test_compare_endpoints(self):
        """Test for compare endpoinst for the fifth internal conditional."""
        endpoint1 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "in_port": 3,
            "in_vlan": 100,
        }
        endpoint2 = {
            "dpid": "00:00:00:00:00:00:00:03",
            "out_port": 3,
            "out_vlan": 100,
        }

        # Test endpoint1 out_vlan != endpoint2 in_vlan
        result = utils._compare_endpoints(endpoint1, endpoint2)

        self.assertTrue(result)

    def test_find_endpoint_b(self):
        """Test find endpoint with interface equals link endpoint B."""
        port = 1

        mock_interface = Interface("interface A", port, MagicMock())
        mock_interface.address = "00:00:00:00:00:00:00:01"
        mock_interface.link = get_link_mock(
            "00:00:00:00:00:00:00:02", "00:00:00:00:00:00:00:01"
        )

        mock_switch = MagicMock()
        mock_switch.get_interface_by_port_no.return_value = mock_interface

        result = utils.find_endpoint(mock_switch, port)
        self.assertEqual(result, mock_interface.link.endpoint_a)

    def test_find_endpoint_a(self):
        """Test find endpoint with interface equals link endpoint A."""
        port = 1

        mock_interface = Interface("interface A", port, MagicMock())
        mock_interface.address = "00:00:00:00:00:00:00:01"
        mock_interface.link = get_link_mock(
            "00:00:00:00:00:00:00:01", "00:00:00:00:00:00:00:03"
        )

        mock_switch = MagicMock()
        mock_switch.get_interface_by_port_no.return_value = mock_interface

        result = utils.find_endpoint(mock_switch, port)
        self.assertEqual(result, mock_interface.link.endpoint_b)

    def test_find_endpoint_link_none(self):
        """Test find endpoint without link."""
        port = 1

        mock_interface = Interface("interface A", port, MagicMock())
        mock_interface.address = "00:00:00:00:00:00:00:01"

        mock_switch = MagicMock()
        mock_switch.get_interface_by_port_no.return_value = mock_interface

        result = utils.find_endpoint(mock_switch, port)
        self.assertIsNone(result)


# pylint: disable=too-many-public-methods, too-many-lines
class TestUtilsWithController(TestCase):
    """Test utils.py."""

    def setUp(self):
        # The decorator run_on_thread is patched, so methods that listen
        # for events do not run on threads while tested.
        # Decorators have to be patched before the methods that are
        # decorated with them are imported.
        patch("kytos.core.helpers.run_on_thread", lambda x: x).start()

        self.controller = get_controller_mock()

        self.addCleanup(patch.stopall)

    def test_clean_circuits__empty(self):
        """Test clean circuits for empty circuits."""
        circuits = MagicMock()
        result = utils.clean_circuits(circuits, self.controller)

        self.assertEqual(result, [])

    def test_clean_circuits__no_sub(self):
        """Test clean circuits with just one circuit."""
        formatted = [
            {
                "dpid": "00:00:00:00:00:00:00:03",
                "in_port": 3,
                "out_port": 2,
                "out_vlan": 200,
                "in_vlan": 100,
            },
        ]

        circuits = []
        circuits.append({"circuit": formatted, "entries": []})

        result = utils.clean_circuits(circuits, self.controller)

        self.assertTrue(len(result) == 1)
        self.assertEqual(formatted, result[0]["circuit"])

    def test_clean_circuits_with_sub_circuit(self):
        """Test clean circuits without sub-circuits."""
        formatted_a = [
            {
                "dpid": "00:00:00:00:00:00:00:01",
            },
            {
                "dpid": "00:00:00:00:00:00:00:03",
            },
        ]
        formatted_b = [
            {
                "dpid": "00:00:00:00:00:00:00:01",
            },
            {
                "dpid": "00:00:00:00:00:00:00:02",
            },
            {
                "dpid": "00:00:00:00:00:00:00:03",
            },
        ]

        circuits = []
        circuits.append({"circuit": formatted_a, "entries": []})
        circuits.append({"circuit": formatted_b, "entries": []})

        # Test cleaning one sub-circuit
        result = utils.clean_circuits(circuits, self.controller)

        # Result must be the circuits without the sub-circuit
        self.assertTrue(len(result) == 1)
        self.assertEqual(formatted_b, result[0]["circuit"])

    def test_clean_circuits_without_sub_circuit(self):
        """Test clean circuits with one sub-circuit."""
        formatted_a = [
            {
                "dpid": "00:00:00:00:00:00:00:01",
            },
            {
                "dpid": "00:00:00:00:00:00:00:02",
            },
        ]
        formatted_b = [
            {
                "dpid": "00:00:00:00:00:00:00:01",
            },
            {
                "dpid": "00:00:00:00:00:00:00:03",
            },
            {
                "dpid": "00:00:00:00:00:00:00:04",
            },
        ]

        circuits = []
        circuits.append({"circuit": formatted_a, "entries": []})
        circuits.append({"circuit": formatted_b, "entries": []})

        # Test circuits withou sub-circuits.
        result = utils.clean_circuits(circuits, self.controller)

        # Result must be equal to the circuits parameter
        self.assertTrue(len(result) == 2)
        self.assertEqual(circuits, result)
