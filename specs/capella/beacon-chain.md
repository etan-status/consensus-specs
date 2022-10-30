# Capella -- The Beacon Chain

## Table of contents

<!-- TOC -->
<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Introduction](#introduction)
- [Custom types](#custom-types)
- [Constants](#constants)
  - [Domain types](#domain-types)
  - [Merkle proofs](#merkle-proofs)
- [Preset](#preset)
  - [Max operations per block](#max-operations-per-block)
  - [Execution](#execution)
- [Containers](#containers)
  - [New containers](#new-containers)
    - [`Withdrawal`](#withdrawal)
    - [`BLSToExecutionChange`](#blstoexecutionchange)
    - [`SignedBLSToExecutionChange`](#signedblstoexecutionchange)
    - [`SyncCommitteeSlashingEvidence`](#synccommitteeslashingevidence)
    - [`SyncCommitteeSlashing`](#synccommitteeslashing)
  - [Extended Containers](#extended-containers)
    - [`ExecutionPayload`](#executionpayload)
    - [`ExecutionPayloadHeader`](#executionpayloadheader)
    - [`BeaconBlockBody`](#beaconblockbody)
    - [`BeaconState`](#beaconstate)
- [Helpers](#helpers)
  - [Predicates](#predicates)
    - [`has_eth1_withdrawal_credential`](#has_eth1_withdrawal_credential)
    - [`is_fully_withdrawable_validator`](#is_fully_withdrawable_validator)
    - [`is_partially_withdrawable_validator`](#is_partially_withdrawable_validator)
    - [`sync_committee_slashing_evidence_has_sync_committee`](#sync_committee_slashing_evidence_has_sync_committee)
    - [`sync_committee_slashing_evidence_has_finality`](#sync_committee_slashing_evidence_has_finality)
    - [`is_valid_sync_committee_slashing_evidence`](#is_valid_sync_committee_slashing_evidence)
- [Beacon chain state transition function](#beacon-chain-state-transition-function)
  - [Block processing](#block-processing)
    - [New `get_expected_withdrawals`](#new-get_expected_withdrawals)
    - [New `process_withdrawals`](#new-process_withdrawals)
    - [Modified `process_execution_payload`](#modified-process_execution_payload)
    - [Modified `process_operations`](#modified-process_operations)
    - [New `process_sync_committee_slashing`](#new-process_sync_committee_slashing)
    - [New `process_bls_to_execution_change`](#new-process_bls_to_execution_change)
- [Testing](#testing)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->
<!-- /TOC -->

## Introduction

Capella is a consensus-layer upgrade containing a number of features related
to validator withdrawals. Including:
* Automatic withdrawals of `withdrawable` validators.
* Partial withdrawals sweep for validators with 0x01 withdrawal
  credentials and balances in excess of `MAX_EFFECTIVE_BALANCE`.
* Operation to change from `BLS_WITHDRAWAL_PREFIX` to
  `ETH1_ADDRESS_WITHDRAWAL_PREFIX` versioned withdrawal credentials to enable withdrawals for a validator.

## Custom types

We define the following Python custom types for type hinting and readability:

| Name | SSZ equivalent | Description |
| - | - | - |
| `WithdrawalIndex` | `uint64` | an index of a `Withdrawal` |

## Constants

### Domain types

| Name | Value |
| - | - |
| `DOMAIN_BLS_TO_EXECUTION_CHANGE` | `DomainType('0x0A000000')` |

### Merkle proofs

| Name | Value |
| - | - |
| `BLOCK_STATE_ROOT_INDEX` | `get_generalized_index(BeaconBlock, 'state_root')` (= 11) |
| `STATE_BLOCK_ROOTS_INDEX` | `get_generalized_index(BeaconState, 'block_roots')` (= 37) |
| `STATE_HISTORICAL_ROOTS_INDEX` | `get_generalized_index(BeaconState, 'historical_roots')` (= 39) |
| `HISTORICAL_BATCH_BLOCK_ROOTS_INDEX` | `get_generalized_index(HistoricalBatch, 'block_roots')` (= 2) |

## Preset

### Max operations per block

| Name | Value |
| - | - |
| `MAX_BLS_TO_EXECUTION_CHANGES` | `2**4` (= 16) |
| `MAX_SYNC_COMMITTEE_SLASHINGS` | `2**0` (= 1) |

### Execution

| Name | Value | Description |
| - | - | - |
| `MAX_WITHDRAWALS_PER_PAYLOAD` | `uint64(2**4)` (= 16) | Maximum amount of withdrawals allowed in each payload |

## Containers

### New containers

#### `Withdrawal`

```python
class Withdrawal(Container):
    index: WithdrawalIndex
    validator_index: ValidatorIndex
    address: ExecutionAddress
    amount: Gwei
```

#### `BLSToExecutionChange`

```python
class BLSToExecutionChange(Container):
    validator_index: ValidatorIndex
    from_bls_pubkey: BLSPubkey
    to_execution_address: ExecutionAddress
```

#### `SignedBLSToExecutionChange`

```python
class SignedBLSToExecutionChange(Container):
    message: BLSToExecutionChange
    signature: BLSSignature
```

#### `SyncCommitteeSlashingEvidence`

```python
class SyncCommitteeSlashingEvidence(Container):
    attested_header: BeaconBlockHeader
    next_sync_committee: SyncCommittee
    next_sync_committee_branch: Vector[Root, floorlog2(NEXT_SYNC_COMMITTEE_INDEX)]
    finalized_header: BeaconBlockHeader
    finality_branch: Vector[Root, floorlog2(FINALIZED_ROOT_INDEX)]
    sync_aggregate: SyncAggregate
    signature_slot: Slot
    sync_committee_pubkeys: Vector[BLSPubkey, SYNC_COMMITTEE_SIZE]
    actual_finalized_block_root: Root
    actual_finalized_branch: List[Root, (
        floorlog2(BLOCK_STATE_ROOT_INDEX)
        + floorlog2(STATE_HISTORICAL_ROOTS_INDEX)
        + 1 + floorlog2(HISTORICAL_ROOTS_LIMIT)
        + floorlog2(HISTORICAL_BATCH_BLOCK_ROOTS_INDEX)
        + 1 + floorlog2(SLOTS_PER_HISTORICAL_ROOT))]
```

#### `SyncCommitteeSlashing`

```python
class SyncCommitteeSlashing(Container):
    slashable_validators: List[ValidatorIndex, SYNC_COMMITTEE_SIZE]
    evidence_1: SyncCommitteeSlashingEvidence
    evidence_2: SyncCommitteeSlashingEvidence
    recent_finalized_block_root: Root
    recent_finalized_slot: Slot
```

### Extended Containers

#### `ExecutionPayload`

```python
class ExecutionPayload(Container):
    # Execution block header fields
    parent_hash: Hash32
    fee_recipient: ExecutionAddress  # 'beneficiary' in the yellow paper
    state_root: Bytes32
    receipts_root: Bytes32
    logs_bloom: ByteVector[BYTES_PER_LOGS_BLOOM]
    prev_randao: Bytes32  # 'difficulty' in the yellow paper
    block_number: uint64  # 'number' in the yellow paper
    gas_limit: uint64
    gas_used: uint64
    timestamp: uint64
    extra_data: ByteList[MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas: uint256
    # Extra payload fields
    block_hash: Hash32  # Hash of execution block
    transactions: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]
    withdrawals: List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]  # [New in Capella]
```

#### `ExecutionPayloadHeader`

```python
class ExecutionPayloadHeader(Container):
    # Execution block header fields
    parent_hash: Hash32
    fee_recipient: ExecutionAddress
    state_root: Bytes32
    receipts_root: Bytes32
    logs_bloom: ByteVector[BYTES_PER_LOGS_BLOOM]
    prev_randao: Bytes32
    block_number: uint64
    gas_limit: uint64
    gas_used: uint64
    timestamp: uint64
    extra_data: ByteList[MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas: uint256
    # Extra payload fields
    block_hash: Hash32  # Hash of execution block
    transactions_root: Root
    withdrawals_root: Root  # [New in Capella]
```

#### `BeaconBlockBody`

```python
class BeaconBlockBody(Container):
    randao_reveal: BLSSignature
    eth1_data: Eth1Data  # Eth1 data vote
    graffiti: Bytes32  # Arbitrary data
    # Operations
    proposer_slashings: List[ProposerSlashing, MAX_PROPOSER_SLASHINGS]
    attester_slashings: List[AttesterSlashing, MAX_ATTESTER_SLASHINGS]
    attestations: List[Attestation, MAX_ATTESTATIONS]
    deposits: List[Deposit, MAX_DEPOSITS]
    voluntary_exits: List[SignedVoluntaryExit, MAX_VOLUNTARY_EXITS]
    sync_aggregate: SyncAggregate
    # Execution
    execution_payload: ExecutionPayload
    # Capella operations
    bls_to_execution_changes: List[SignedBLSToExecutionChange, MAX_BLS_TO_EXECUTION_CHANGES]  # [New in Capella]
    sync_committee_slashings: List[SyncCommitteeSlashing, MAX_SYNC_COMMITTEE_SLASHINGS]  # [New in Capella]
```

#### `BeaconState`

```python
class BeaconState(Container):
    # Versioning
    genesis_time: uint64
    genesis_validators_root: Root
    slot: Slot
    fork: Fork
    # History
    latest_block_header: BeaconBlockHeader
    block_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]
    state_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]
    historical_roots: List[Root, HISTORICAL_ROOTS_LIMIT]
    # Eth1
    eth1_data: Eth1Data
    eth1_data_votes: List[Eth1Data, EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH]
    eth1_deposit_index: uint64
    # Registry
    validators: List[Validator, VALIDATOR_REGISTRY_LIMIT]
    balances: List[Gwei, VALIDATOR_REGISTRY_LIMIT]
    # Randomness
    randao_mixes: Vector[Bytes32, EPOCHS_PER_HISTORICAL_VECTOR]
    # Slashings
    slashings: Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]  # Per-epoch sums of slashed effective balances
    # Participation
    previous_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]
    current_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]
    # Finality
    justification_bits: Bitvector[JUSTIFICATION_BITS_LENGTH]  # Bit set for every recent justified epoch
    previous_justified_checkpoint: Checkpoint
    current_justified_checkpoint: Checkpoint
    finalized_checkpoint: Checkpoint
    # Inactivity
    inactivity_scores: List[uint64, VALIDATOR_REGISTRY_LIMIT]
    # Sync
    current_sync_committee: SyncCommittee
    next_sync_committee: SyncCommittee
    # Execution
    latest_execution_payload_header: ExecutionPayloadHeader
    # Withdrawals
    next_withdrawal_index: WithdrawalIndex  # [New in Capella]
    next_withdrawal_validator_index: ValidatorIndex  # [New in Capella]
```

## Helpers

### Predicates

#### `has_eth1_withdrawal_credential`

```python
def has_eth1_withdrawal_credential(validator: Validator) -> bool:
    """
    Check if ``validator`` has an 0x01 prefixed "eth1" withdrawal credential.
    """
    return validator.withdrawal_credentials[:1] == ETH1_ADDRESS_WITHDRAWAL_PREFIX
```

#### `is_fully_withdrawable_validator`

```python
def is_fully_withdrawable_validator(validator: Validator, balance: Gwei, epoch: Epoch) -> bool:
    """
    Check if ``validator`` is fully withdrawable.
    """
    return (
        has_eth1_withdrawal_credential(validator)
        and validator.withdrawable_epoch <= epoch
        and balance > 0
    )
```

#### `is_partially_withdrawable_validator`

```python
def is_partially_withdrawable_validator(validator: Validator, balance: Gwei) -> bool:
    """
    Check if ``validator`` is partially withdrawable.
    """
    has_max_effective_balance = validator.effective_balance == MAX_EFFECTIVE_BALANCE
    has_excess_balance = balance > MAX_EFFECTIVE_BALANCE
    return has_eth1_withdrawal_credential(validator) and has_max_effective_balance and has_excess_balance
```

#### `sync_committee_slashing_evidence_has_sync_committee`

```python
def sync_committee_slashing_evidence_has_sync_committee(evidence: SyncCommitteeSlashingEvidence) -> bool:
    return evidence.next_sync_committee_branch != [Root() for _ in range(floorlog2(NEXT_SYNC_COMMITTEE_INDEX))]
```

#### `sync_committee_slashing_evidence_has_finality`

```python
def sync_committee_slashing_evidence_has_finality(evidence: SyncCommitteeSlashingEvidence) -> bool:
    return evidence.finality_branch != [Root() for _ in range(floorlog2(FINALIZED_ROOT_INDEX))]
```

#### `is_valid_sync_committee_slashing_evidence`

```python
def is_valid_sync_committee_slashing_evidence(evidence: SyncCommitteeSlashingEvidence,
                                              recent_finalized_block_root: Root,
                                              recent_finalized_slot: Slot,
                                              genesis_validators_root: Root) -> bool:
    # Verify sync committee has sufficient participants
    sync_aggregate = evidence.sync_aggregate
    if sum(sync_aggregate.sync_committee_bits) < MIN_SYNC_COMMITTEE_PARTICIPANTS:
        return False

    # Verify that the `finality_branch`, if present, confirms `finalized_header`
    # to match the finalized checkpoint root saved in the state of `attested_header`.
    # Note that the genesis finalized checkpoint root is represented as a zero hash.
    if not sync_committee_slashing_evidence_has_finality(evidence):
        if evidence.actual_finalized_block_root != Root():
            return False
        if evidence.finalized_header != BeaconBlockHeader():
            return False
    else:
        if evidence.finalized_header.slot == GENESIS_SLOT:
            if evidence.actual_finalized_block_root != Root():
                return False
            if evidence.finalized_header != BeaconBlockHeader():
                return False
            finalized_root = Root()
        else:
            finalized_root = hash_tree_root(evidence.finalized_header)
        if not is_valid_merkle_branch(
            leaf=finalized_root,
            branch=evidence.finality_branch,
            depth=floorlog2(FINALIZED_ROOT_INDEX),
            index=get_subtree_index(FINALIZED_ROOT_INDEX),
            root=evidence.attested_header.state_root,
        ):
            return False

    # Verify that the `next_sync_committee`, if present, actually is the next sync committee saved in the
    # state of the `attested_header`
    if not sync_committee_slashing_evidence_has_sync_committee(evidence):
        if evidence.next_sync_committee != SyncCommittee():
            return False
    else:
        if not is_valid_merkle_branch(
            leaf=hash_tree_root(evidence.next_sync_committee),
            branch=evidence.next_sync_committee_branch,
            depth=floorlog2(NEXT_SYNC_COMMITTEE_INDEX),
            index=get_subtree_index(NEXT_SYNC_COMMITTEE_INDEX),
            root=evidence.attested_header.state_root,
        ):
            return False

    # Verify that the `actual_finalized_block_root`, if present, is confirmed by `actual_finalized_branch`
    # to be the block root at slot `finalized_header.slot` relative to `recent_finalized_block_root`
    if recent_finalized_block_root == Root():
        if evidence.actual_finalized_block_root != Root():
            return False
    if evidence.actual_finalized_block_root == Root():
        if len(evidence.actual_finalized_branch) != 0:
            return False
    else:
        finalized_slot = evidence.finalized_header.slot
        if recent_finalized_slot < finalized_slot:
            return False
        distance = recent_finalized_slot - finalized_slot
        if distance == 0:
            gindex = GeneralizedIndex(1)
        else:
            gindex = BLOCK_STATE_ROOT_INDEX
            if distance <= SLOTS_PER_HISTORICAL_ROOT:
                gindex = (gindex << floorlog2(STATE_BLOCK_ROOTS_INDEX)) + STATE_BLOCK_ROOTS_INDEX
            else:
                gindex = (gindex << floorlog2(STATE_HISTORICAL_ROOTS_INDEX)) + STATE_HISTORICAL_ROOTS_INDEX
                gindex = (gindex << uint64(1)) + 0  # `mix_in_length`
                historical_batch_index = finalized_slot // SLOTS_PER_HISTORICAL_ROOT
                gindex = (gindex << floorlog2(HISTORICAL_ROOTS_LIMIT)) + historical_batch_index
                gindex = (gindex << floorlog2(HISTORICAL_BATCH_BLOCK_ROOTS_INDEX)) + HISTORICAL_BATCH_BLOCK_ROOTS_INDEX
            gindex = (gindex << uint64(1)) + 0  # `mix_in_length`
            block_root_index = finalized_slot % SLOTS_PER_HISTORICAL_ROOT
            gindex = (gindex << floorlog2(SLOTS_PER_HISTORICAL_ROOT)) + block_root_index
        if len(evidence.actual_finalized_branch) != floorlog2(gindex):
            return False
        if not is_valid_merkle_branch(
            leaf=evidence.actual_finalized_block_root,
            branch=evidence.actual_finalized_branch,
            depth=floorlog2(gindex),
            index=get_subtree_index(gindex),
            root=recent_finalized_block_root,
        ):
            return False

    # Verify sync committee aggregate signature
    sync_committee_pubkeys = evidence.sync_committee_pubkeys
    participant_pubkeys = [
        pubkey for (bit, pubkey) in zip(sync_aggregate.sync_committee_bits, sync_committee_pubkeys)
        if bit
    ]
    fork_version = compute_fork_version(compute_epoch_at_slot(evidence.signature_slot))
    domain = compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)
    signing_root = compute_signing_root(evidence.attested_header, domain)
    return bls.FastAggregateVerify(participant_pubkeys, signing_root, sync_aggregate.sync_committee_signature)
```

## Beacon chain state transition function

### Block processing

```python
def process_block(state: BeaconState, block: BeaconBlock) -> None:
    process_block_header(state, block)
    if is_execution_enabled(state, block.body):
        process_withdrawals(state, block.body.execution_payload)  # [New in Capella]
        process_execution_payload(state, block.body.execution_payload, EXECUTION_ENGINE)  # [Modified in Capella]
    process_randao(state, block.body)
    process_eth1_data(state, block.body)
    process_operations(state, block.body)  # [Modified in Capella]
    process_sync_aggregate(state, block.body.sync_aggregate)
```

#### New `get_expected_withdrawals`

```python
def get_expected_withdrawals(state: BeaconState) -> Sequence[Withdrawal]:
    epoch = get_current_epoch(state)
    withdrawal_index = state.next_withdrawal_index
    validator_index = state.next_withdrawal_validator_index
    withdrawals: List[Withdrawal] = []
    for _ in range(len(state.validators)):
        validator = state.validators[validator_index]
        balance = state.balances[validator_index]
        if is_fully_withdrawable_validator(validator, balance, epoch):
            withdrawals.append(Withdrawal(
                index=withdrawal_index,
                validator_index=validator_index,
                address=ExecutionAddress(validator.withdrawal_credentials[12:]),
                amount=balance,
            ))
            withdrawal_index += WithdrawalIndex(1)
        elif is_partially_withdrawable_validator(validator, balance):
            withdrawals.append(Withdrawal(
                index=withdrawal_index,
                validator_index=validator_index,
                address=ExecutionAddress(validator.withdrawal_credentials[12:]),
                amount=balance - MAX_EFFECTIVE_BALANCE,
            ))
            withdrawal_index += WithdrawalIndex(1)
        if len(withdrawals) == MAX_WITHDRAWALS_PER_PAYLOAD:
            break
        validator_index = ValidatorIndex((validator_index + 1) % len(state.validators))
    return withdrawals
```
        
#### New `process_withdrawals`

```python
def process_withdrawals(state: BeaconState, payload: ExecutionPayload) -> None:
    expected_withdrawals = get_expected_withdrawals(state)
    assert len(payload.withdrawals) == len(expected_withdrawals)

    for expected_withdrawal, withdrawal in zip(expected_withdrawals, payload.withdrawals):
        assert withdrawal == expected_withdrawal
        decrease_balance(state, withdrawal.validator_index, withdrawal.amount)
    if len(expected_withdrawals) > 0:
        latest_withdrawal = expected_withdrawals[-1]
        state.next_withdrawal_index = WithdrawalIndex(latest_withdrawal.index + 1)
        next_validator_index = ValidatorIndex((latest_withdrawal.validator_index + 1) % len(state.validators))
        state.next_withdrawal_validator_index = next_validator_index
```

#### Modified `process_execution_payload`

*Note*: The function `process_execution_payload` is modified to use the new `ExecutionPayloadHeader` type.

```python
def process_execution_payload(state: BeaconState, payload: ExecutionPayload, execution_engine: ExecutionEngine) -> None:
    # Verify consistency of the parent hash with respect to the previous execution payload header
    if is_merge_transition_complete(state):
        assert payload.parent_hash == state.latest_execution_payload_header.block_hash
    # Verify prev_randao
    assert payload.prev_randao == get_randao_mix(state, get_current_epoch(state))
    # Verify timestamp
    assert payload.timestamp == compute_timestamp_at_slot(state, state.slot)
    # Verify the execution payload is valid
    assert execution_engine.notify_new_payload(payload)
    # Cache execution payload header
    state.latest_execution_payload_header = ExecutionPayloadHeader(
        parent_hash=payload.parent_hash,
        fee_recipient=payload.fee_recipient,
        state_root=payload.state_root,
        receipts_root=payload.receipts_root,
        logs_bloom=payload.logs_bloom,
        prev_randao=payload.prev_randao,
        block_number=payload.block_number,
        gas_limit=payload.gas_limit,
        gas_used=payload.gas_used,
        timestamp=payload.timestamp,
        extra_data=payload.extra_data,
        base_fee_per_gas=payload.base_fee_per_gas,
        block_hash=payload.block_hash,
        transactions_root=hash_tree_root(payload.transactions),
        withdrawals_root=hash_tree_root(payload.withdrawals),  # [New in Capella]
    )
```

#### Modified `process_operations`

*Note*: The function `process_operations` is modified to process `BLSToExecutionChange` operations included in the block.

```python
def process_operations(state: BeaconState, body: BeaconBlockBody) -> None:
    # Verify that outstanding deposits are processed up to the maximum number of deposits
    assert len(body.deposits) == min(MAX_DEPOSITS, state.eth1_data.deposit_count - state.eth1_deposit_index)

    def for_ops(operations: Sequence[Any], fn: Callable[[BeaconState, Any], None]) -> None:
        for operation in operations:
            fn(state, operation)

    for_ops(body.proposer_slashings, process_proposer_slashing)
    for_ops(body.attester_slashings, process_attester_slashing)
    for_ops(body.sync_committee_slashings, process_sync_committee_slashing)  # [New in Capella]
    for_ops(body.attestations, process_attestation)
    for_ops(body.deposits, process_deposit)
    for_ops(body.voluntary_exits, process_voluntary_exit)
    for_ops(body.bls_to_execution_changes, process_bls_to_execution_change)  # [New in Capella]
```

#### New `process_sync_committee_slashing`

```python
def process_sync_committee_slashing(state: BeaconState, sync_committee_slashing: SyncCommitteeSlashing) -> None:
    is_slashable = False

    # Check that evidence is ordered descending by `attested_header.slot` and is not from the future
    evidence_1 = sync_committee_slashing.evidence_1
    evidence_2 = sync_committee_slashing.evidence_2
    assert state.slot >= evidence_1.signature_slot > evidence_1.attested_header.slot >= evidence_1.finalized_header.slot
    assert state.slot >= evidence_2.signature_slot > evidence_2.attested_header.slot >= evidence_2.finalized_header.slot
    assert evidence_1.attested_header.slot >= evidence_2.attested_header.slot

    # Only conflicting data among the current and previous sync committee period is slashable;
    # on new periods, the sync committee initially signs blocks in a previous sync committee period.
    # This allows a validator synced to a malicious checkpoint to contribute again in a future period
    evidence_1_attested_period = compute_sync_committee_period_at_slot(evidence_1.attested_header.slot)
    evidence_2_attested_period = compute_sync_committee_period_at_slot(evidence_2.attested_header.slot)
    assert evidence_1_attested_period <= evidence_2_attested_period + 1

    # It is not allowed to sign conflicting `attested_header` for a given slot
    if evidence_1.attested_header.slot == evidence_2.attested_header.slot:
        if evidence_1.attested_header != evidence_2.attested_header:
            is_slashable = True

    # It is not allowed to sign conflicting finalized `next_sync_committee`
    evidence_1_finalized_period = compute_sync_committee_period_at_slot(evidence_1.finalized_header.slot)
    evidence_2_finalized_period = compute_sync_committee_period_at_slot(evidence_2.finalized_header.slot)
    if (
        evidence_1_attested_period == evidence_2_attested_period
        and evidence_1_finalized_period == evidence_1_attested_period
        and evidence_2_finalized_period == evidence_2_attested_period
        and sync_committee_slashing_evidence_has_finality(evidence_1)
        and sync_committee_slashing_evidence_has_finality(evidence_2)
        and sync_committee_slashing_evidence_has_sync_committee(evidence_1)
        and sync_committee_slashing_evidence_has_sync_committee(evidence_2)
    ):
        if evidence_1.next_sync_committee != evidence_2.next_sync_committee:
            is_slashable = True

    # It is not allowed to sign a non-linear finalized history
    recent_finalized_slot = sync_committee_slashing.recent_finalized_slot
    recent_finalized_block_root = sync_committee_slashing.recent_finalized_block_root
    if (
        not sync_committee_slashing_evidence_has_finality(evidence_1)
        or not sync_committee_slashing_evidence_has_finality(evidence_2)
    ):
        assert recent_finalized_block_root == Root()
    if recent_finalized_block_root == Root():
        assert recent_finalized_slot == 0
    else:
        # Merkle proofs may be included to indicate that `finalized_header` does not match
        # the `actual_finalized_block_root` relative to a given `recent_finalized_block_root`.
        # The finalized history is linear. Therefore, a mismatch indicates signing on an unrelated chain.
        # Note that it is not slashable to sign solely an alternate history, as long as it is consistent.
        # This allows a validator synced to a malicious checkpoint to contribute again in a future period
        linear_1 = (evidence_1.actual_finalized_block_root == hash_tree_root(evidence_1.finalized_header))
        linear_2 = (evidence_2.actual_finalized_block_root == hash_tree_root(evidence_2.finalized_header))
        assert not linear_1 or not linear_2
        assert linear_1 or linear_2  # Do not slash on signing solely an alternate history

        # `actual_finalized_branch` may be rooted in the provided `finalized_header` with highest slot
        rooted_in_evidence_1 = (
            evidence_1.finalized_header.slot >= evidence_2.finalized_header.slot
            and recent_finalized_slot == evidence_1.finalized_header.slot
            and recent_finalized_block_root == evidence_1.actual_finalized_block_root and linear_1
        )
        rooted_in_evidence_2 = (
            evidence_2.finalized_header.slot >= evidence_1.finalized_header.slot
            and recent_finalized_slot == evidence_2.finalized_header.slot
            and recent_finalized_block_root == evidence_2.actual_finalized_block_root and linear_2
        )

        # Alternatively, if evidence about non-linearity cannot be obtained directly from an attack,
        # it can be proven that one of the `finalized_header` is part of the canonical finalized chain
        # that our beacon node is synced to, while the other `finalized_header` is unrelated.
        rooted_in_canonical = (
            recent_finalized_slot < state.slot <= recent_finalized_slot + SLOTS_PER_HISTORICAL_ROOT
            and recent_finalized_slot <= compute_start_slot_at_epoch(state.finalized_checkpoint.epoch)
            and recent_finalized_block_root == state.state_roots[recent_finalized_slot % SLOTS_PER_HISTORICAL_ROOT]
        )

        assert rooted_in_evidence_1 or rooted_in_evidence_2 or rooted_in_canonical
        is_slashable = True

    assert is_slashable

    # Check that slashable validators are sorted, known, and participated in both signatures
    will_slash_any = False
    sync_aggregate_1 = evidence_1.sync_aggregate
    sync_aggregate_2 = evidence_2.sync_aggregate
    sync_committee_pubkeys_1 = evidence_1.sync_committee_pubkeys
    sync_committee_pubkeys_2 = evidence_2.sync_committee_pubkeys
    participant_pubkeys_1 = [
        pubkey for (bit, pubkey) in zip(sync_aggregate_1.sync_committee_bits, sync_committee_pubkeys_1)
        if bit
    ]
    participant_pubkeys_2 = [
        pubkey for (bit, pubkey) in zip(sync_aggregate_2.sync_committee_bits, sync_committee_pubkeys_2)
        if bit
    ]
    slashable_validators = sync_committee_slashing.slashable_validators
    num_validators = len(state.validators)
    for i, index in enumerate(slashable_validators):
        assert (
            index < num_validators
            and (i == 0 or index > slashable_validators[i - 1])
        )
        assert state.validators[index].pubkey in participant_pubkeys_1
        assert state.validators[index].pubkey in participant_pubkeys_2
        if is_slashable_validator(state.validators[index], get_current_epoch(state)):
            will_slash_any = True
    assert will_slash_any

    # Validate evidence, including signatures
    assert is_valid_sync_committee_slashing_evidence(
        evidence_1,
        recent_finalized_block_root,
        recent_finalized_slot,
        state.genesis_validator_root,
    )
    assert is_valid_sync_committee_slashing_evidence(
        evidence_2,
        recent_finalized_block_root,
        recent_finalized_slot,
        state.genesis_validator_root,
    )

    # Perform slashing
    for index in slashable_validators:
        if is_slashable_validator(state.validators[index], get_current_epoch(state)):
            slash_validator(state, index)
```

#### New `process_bls_to_execution_change`

```python
def process_bls_to_execution_change(state: BeaconState,
                                    signed_address_change: SignedBLSToExecutionChange) -> None:
    address_change = signed_address_change.message

    assert address_change.validator_index < len(state.validators)

    validator = state.validators[address_change.validator_index]

    assert validator.withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX
    assert validator.withdrawal_credentials[1:] == hash(address_change.from_bls_pubkey)[1:]

    domain = get_domain(state, DOMAIN_BLS_TO_EXECUTION_CHANGE)
    signing_root = compute_signing_root(address_change, domain)
    assert bls.Verify(address_change.from_bls_pubkey, signing_root, signed_address_change.signature)

    validator.withdrawal_credentials = (
        ETH1_ADDRESS_WITHDRAWAL_PREFIX
        + b'\x00' * 11
        + address_change.to_execution_address
    )
```

## Testing

*Note*: The function `initialize_beacon_state_from_eth1` is modified for pure Capella testing only.
Modifications include:
1. Use `CAPELLA_FORK_VERSION` as the previous and current fork version.
2. Utilize the Capella `BeaconBlockBody` when constructing the initial `latest_block_header`.

```python
def initialize_beacon_state_from_eth1(eth1_block_hash: Hash32,
                                      eth1_timestamp: uint64,
                                      deposits: Sequence[Deposit],
                                      execution_payload_header: ExecutionPayloadHeader=ExecutionPayloadHeader()
                                      ) -> BeaconState:
    fork = Fork(
        previous_version=CAPELLA_FORK_VERSION,  # [Modified in Capella] for testing only
        current_version=CAPELLA_FORK_VERSION,  # [Modified in Capella]
        epoch=GENESIS_EPOCH,
    )
    state = BeaconState(
        genesis_time=eth1_timestamp + GENESIS_DELAY,
        fork=fork,
        eth1_data=Eth1Data(block_hash=eth1_block_hash, deposit_count=uint64(len(deposits))),
        latest_block_header=BeaconBlockHeader(body_root=hash_tree_root(BeaconBlockBody())),
        randao_mixes=[eth1_block_hash] * EPOCHS_PER_HISTORICAL_VECTOR,  # Seed RANDAO with Eth1 entropy
    )

    # Process deposits
    leaves = list(map(lambda deposit: deposit.data, deposits))
    for index, deposit in enumerate(deposits):
        deposit_data_list = List[DepositData, 2**DEPOSIT_CONTRACT_TREE_DEPTH](*leaves[:index + 1])
        state.eth1_data.deposit_root = hash_tree_root(deposit_data_list)
        process_deposit(state, deposit)

    # Process activations
    for index, validator in enumerate(state.validators):
        balance = state.balances[index]
        validator.effective_balance = min(balance - balance % EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE)
        if validator.effective_balance == MAX_EFFECTIVE_BALANCE:
            validator.activation_eligibility_epoch = GENESIS_EPOCH
            validator.activation_epoch = GENESIS_EPOCH

    # Set genesis validators root for domain separation and chain versioning
    state.genesis_validators_root = hash_tree_root(state.validators)

    # Fill in sync committees
    # Note: A duplicate committee is assigned for the current and next committee at genesis
    state.current_sync_committee = get_next_sync_committee(state)
    state.next_sync_committee = get_next_sync_committee(state)

    # Initialize the execution payload header
    state.latest_execution_payload_header = execution_payload_header

    return state
```
