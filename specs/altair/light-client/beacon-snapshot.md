# Altair Light Client -- Beacon Snapshot

## Table of contents

<!-- TOC -->
<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Introduction](#introduction)
- [Custom types](#custom-types)
- [Constants](#constants)
- [Containers](#containers)
  - [`LightClientBeaconSnapshot`](#lightclientbeaconsnapshot)
- [Helper functions](#helper-functions)
  - [`state_roots_gindex_at_slot`](#state_roots_gindex_at_slot)
  - [`historical_roots_gindex_at_slot`](#historical_roots_gindex_at_slot)
  - [`first_historical_root_gindex_at_slot`](#first_historical_root_gindex_at_slot)
  - [`normalize_merkle_branch`](#normalize_merkle_branch)
- [Beacon snapshot validation](#beacon-snapshot-validation)
  - [`validate_light_client_beacon_snapshot`](#validate_light_client_beacon_snapshot)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->
<!-- /TOC -->

## Introduction

This document describes how full nodes can initialize the `BeaconState` after syncing to a recent beacon header using the [light client](./light-client.md) sync protocol.

## Custom types

| Name | SSZ equivalent | Description
| - | - | - |
| `StateBranch` | `Vector[Bytes32, ceillog2(SLOTS_PER_HISTORICAL_ROOT)]` | Merkle branch of an entry within a `state_roots` vector |
| `HistoricalBranch` | `Vector[Bytes32, MAX_HISTORICAL_BRANCH_DEPTH]` | Merkle branch of a `state_roots` entry within a `BeaconState`. May be embedded in a historical accumulator |

## Constants

| Name | Value |
| - | - |
| `STATE_ROOTS_GINDEX` | `get_generalized_index(BeaconState, 'state_roots')` (= 38) |
| `HISTORICAL_ROOTS_GINDEX` | `get_generalized_index(BeaconState, 'historical_roots')` (= 39) |
| `MAX_HISTORICAL_BRANCH_DEPTH` | `1 + ceillog2(HISTORICAL_ROOTS_LIMIT) + 1 + floorlog2(HISTORICAL_ROOTS_GINDEX)` (= 31) |

## Containers

### `LightClientBeaconSnapshot`

```python
class LightClientBeaconSnapshot(Container):
    # Update matching the requested sync committee period
    update: LightClientFinalityUpdate
    # Inclusion proof of the historical `state_roots` accumulator for the sync
    # committee period indicated by `update.finalized_header.beacon.slot`,
    # corresponding to `update.attested_header.beacon.state_root`
    state_summary_root: Root
    historical_branch: HistoricalBranch
    # Post-state root at the start slot of the sync committee period
    # indicated by `update.finalized_header.beacon.slot`,
    # corresponding to `state_summary_root`
    state_root: Root
    state_branch: StateBranch
```

## Helper functions

### `state_roots_gindex_at_slot`

```python
def state_roots_gindex_at_slot(slot: Slot) -> GeneralizedIndex:
    # pylint: disable=unused-argument
    return STATE_ROOTS_GINDEX
```

### `historical_roots_gindex_at_slot`

```python
def historical_roots_gindex_at_slot(slot: Slot) -> GeneralizedIndex:
    # pylint: disable=unused-argument
    return HISTORICAL_ROOTS_GINDEX
```

### `first_historical_root_gindex_at_slot`

```python
def first_historical_root_gindex_at_slot(slot: Slot) -> GeneralizedIndex:
    depth = ceillog2(HISTORICAL_ROOTS_LIMIT) + 1  # SSZ `mix_in_length`
    return historical_roots_gindex_at_slot(slot) << depth
```

### `normalize_merkle_branch`

```python
def normalize_merkle_branch(branch: Sequence[Bytes32],
                            gindex: GeneralizedIndex) -> Sequence[Bytes32]:
    depth = floorlog2(gindex)
    num_extra = depth - len(branch)
    return [Bytes32()] * num_extra + [*branch]
```

## Beacon snapshot validation

After syncing a `store` object of type `LightClientStore`, a light client can transition to a full node by obtaining a `snapshot` object of type `LightClientBeaconSnapshot` by sync committee period and root. For the `snapshot` request:

- The sync committee period is indicated by `store.finalized_header.beacon.slot`
- The sync committee root is indicated by `store.current_sync_committee.hash_tree_root()`

### `validate_light_client_beacon_snapshot`

```python
def validate_light_client_beacon_snapshot(store: LightClientStore,
                                          snapshot: LightClientBeaconSnapshot,
                                          current_slot: Slot,
                                          genesis_validators_root: Root) -> None:
    store_period = compute_sync_committee_period_at_slot(store.finalized_header.beacon.slot)
    sync_committee = store.current_sync_committee
    update = snapshot.update

    # Verify supermajority (> 2/3) sync committee participation
    sync_committee_bits = update.sync_aggregate.sync_committee_bits
    assert len(sync_committee_bits) * 3 >= len(sync_committee_bits) * 2

    # Verify update is for the requested store sync committee period
    assert is_valid_light_client_header(update.attested_header)
    update_attested_slot = update.attested_header.beacon.slot
    update_finalized_slot = update.finalized_header.beacon.slot
    assert current_slot >= update.signature_slot > update_attested_slot > update_finalized_slot
    update_signature_period = compute_sync_committee_period_at_slot(update.signature_slot)
    update_attested_period = compute_sync_committee_period_at_slot(update_attested_slot)
    assert update_signature_period == update_attested_period == store_period

    # Verify finalized header corresponds to attested header
    validate_light_client_finality_branch(update)

    # Verify that `state_summary_root` corresponds to `attested_header`
    update_finalized_period = compute_sync_committee_period_at_slot(update_finalized_slot)
    assert EPOCHS_PER_SYNC_COMMITTEE_PERIOD == SLOTS_PER_HISTORICAL_ROOT
    if update_finalized_period == update_attested_period:
        historical_gindex = state_roots_gindex_at_slot(update_attested_slot)
    else:
        assert update_finalized_period < HISTORICAL_ROOTS_LIMIT
        historical_gindex = (
            first_historical_root_gindex_at_slot(update_attested_slot)
            + update_finalized_period
        ) << 1 + 1  # State root is at right child node
    assert is_valid_normalized_merkle_branch(
        leaf=snapshot.state_summary_root,
        branch=snapshot.historical_branch,
        gindex=historical_gindex,
        root=update.attested_header.beacon.state_root,
    )

    # Verify that `state_root` corresponds to `state_summary_root`
    assert is_valid_merkle_branch(
        leaf=snapshot.state_root,
        branch=snapshot.state_branch,
        depth=ceillog2(SLOTS_PER_HISTORICAL_ROOT),
        index=0,  # Start slot of the sync committee period
        root=snapshot.state_summary_root
    )

    # Verify sync committee aggregate signature
    validate_light_client_sync_aggregate(update, sync_committee, genesis_validators_root)
```
