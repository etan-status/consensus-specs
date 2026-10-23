from eth_consensus_specs.test.context import (
    always_bls,
    expect_assertion_error,
    spec_state_test,
    with_electra_and_later,
    with_presets,
)
from eth_consensus_specs.test.helpers.attestations import get_valid_attestation
from eth_consensus_specs.test.helpers.constants import MINIMAL
from eth_consensus_specs.utils import bls


@with_electra_and_later
@with_presets([MINIMAL], reason="needs two committees per slot")
@spec_state_test
@always_bls
def test_compute_on_chain_aggregate_cancelling_participants(spec, state):
    network_aggregates = [
        get_valid_attestation(
            spec,
            state,
            index=index,
            filter_participant_set=lambda comm: {min(comm)},
            signed=True,
        )
        for index in range(2)
    ]
    signature = bls.bytes96_to_G2(network_aggregates[0].signature)
    network_aggregates[1].signature = bls.G2_to_bytes96(bls.neg(signature))

    expect_assertion_error(lambda: spec.compute_on_chain_aggregate(network_aggregates))
