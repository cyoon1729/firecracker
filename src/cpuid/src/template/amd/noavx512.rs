// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::bit_helper::BitHelper;
use crate::cpu_leaf::*;
use crate::transformer::*;
use kvm_bindings::{kvm_cpuid_entry2, CpuId};

fn update_structured_extended_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0x7::index0::*;

    if entry.index == 0 {
        entry
            .ebx
            .write_bit(ebx::AVX512F_BITINDEX, false)
            .write_bit(ebx::AVX512DQ_BITINDEX, false)
            .write_bit(ebx::AVX512IFMA_BITINDEX, false)
            .write_bit(ebx::AVX512PF_BITINDEX, false)
            .write_bit(ebx::AVX512ER_BITINDEX, false)
            .write_bit(ebx::AVX512CD_BITINDEX, false)
            .write_bit(ebx::AVX512BW_BITINDEX, false)
            .write_bit(ebx::AVX512VL_BITINDEX, false);

        entry
            .ecx
            .write_bit(ecx::AVX512_VBMI_BITINDEX, false)
            .write_bit(ecx::AVX512_VNNI_BITINDEX, false)
            .write_bit(ecx::AVX512_VPOPCNTDQ_BITINDEX, false);

        entry
            .edx
            .write_bit(edx::AVX512_4VNNIW_BITINDEX, false)
            .write_bit(edx::AVX512_4FMAPS_BITINDEX, false);
    }

    Ok(())
}

fn update_xsave_features_entry(
    entry: &mut kvm_cpuid_entry2,
    _vm_spec: &VmSpec,
) -> Result<(), Error> {
    use crate::cpu_leaf::leaf_0xd::*;

    if entry.index == 0 {
        entry
            .eax
            .write_bits_in_range(&index0::eax::AVX512_STATE_BITRANGE, 0);
    }

    Ok(())
}

struct NoAvx512CpuidTransformer {}

impl CpuidTransformer for NoAvx512CpuidTransformer {
    fn entry_transformer_fn(&self, entry: &mut kvm_cpuid_entry2) -> Option<EntryTransformerFn> {
        match entry.function {
            leaf_0x7::LEAF_NUM => Some(update_structured_extended_entry),
            leaf_0xd::LEAF_NUM => Some(update_xsave_features_entry),
            _ => None,
        }
    }
}

/// Masks AVX-512 CPUID leaves and XSAVE state bits.
pub fn set_cpuid_entries(kvm_cpuid: &mut CpuId, vm_spec: &VmSpec) -> Result<(), Error> {
    NoAvx512CpuidTransformer {}.process_cpuid(kvm_cpuid, vm_spec)
}
