# Test status on a clean checkout

Measured by running every `tests/test_*.py` module (`python -m unittest tests.<name>`, 90 s timeout) in a throwaway copy of this directory with empty `build/` and `cache/` folders, on the maintainer's Windows machine with the toolchain installed but **without** any original game files, evidence, snapshots, `third_party/` clones or the unpublished internal task-queue files. Classification of failures is by error message and by what the module's source references; it is a triage aid, not a proof.

| Category | Modules | Meaning |
|---|---|---|
| PASS | 92 | Runs and passes on a clean checkout |
| BLOCKED | 364 | Cannot run here because an external or unpublished input is missing. **Not** counted as failures |
| NEEDS TRIAGE | 10 | Failing for reasons not yet attributed; may be real failures or stale pins |

The counts were measured on the sanitised sources; they are identical to those measured before the byte vectors were replaced by hash checks (every module has the same status).

Total modules: 466.

## Blocked, by missing input

| Missing input | Modules |
|---|---|
| needs evidence/ inputs (not published) | 171 |
| needs third_party clone | 92 |
| script-style; needs original files/evidence | 45 |
| needs pcrecomp lifter dependency | 21 |
| needs unpublished internal task-queue files | 13 |
| needs DOSBox-X oracle sandbox | 11 |
| needs work/ artifacts (not published) | 7 |
| needs generated build outputs | 3 |
| needs original game files | 1 |

## Needs triage (candidate real failures)

- `test_current_cd_present_gate_projection_work3` - needs unpublished internal task-queue files (reclassify as BLOCKED)
- `test_dpmi_alloc_contract_work3` - needs unpublished internal task-queue files (reclassify as BLOCKED)
- `test_dpmi_lock_resume_work3` - needs unpublished internal task-queue files (reclassify as BLOCKED)
- `test_gw_func_coverage` - script-style module, no unittest cases; run manually
- `test_gw_video_surface_contract` - script-style module, no unittest cases; run manually
- `test_native_dpmi_0200_w1_058` - pins source hashes (`gw_dos_services.h`, `dos_services.py`) that no longer match - stale pin or genuine drift
- `test_taskq_project_metrics` - needs unpublished internal task-queue files (reclassify as BLOCKED)
- `test_taskq_transitions` - needs unpublished internal task-queue files (reclassify as BLOCKED)
- `test_w3_165_wscreen_decoder_boundary` - imports a name missing from an unpublished/changed runner
- `test_w3_260_a0000_video_mapping` - 2 assertion failures; cause not yet determined

## Passing modules

- `test_65f20_x86_math_vectors`
- `test_dos_block_contract_harness`
- `test_dos_filesystem`
- `test_dos_filesystem_iso_work2`
- `test_host_devices`
- `test_iso9660_cue_work2`
- `test_native_alloc_chain_w1_062`
- `test_native_ax0501_post_ah25_w1_061`
- `test_native_dos_ah25_w1_060`
- `test_native_dos_ah35_w1_059`
- `test_recomp_bridge`
- `test_w1_068_native_dynamic_0501`
- `test_w1_069_ax0300_frame_audit`
- `test_w1_077_native_gwerr_lifecycle`
- `test_w1_093_repeat_heap_guard`
- `test_w1_102_ax4400_active_file`
- `test_w3_070_rationalalloc_return_capture`
- `test_w3_071_ah44_capture_evidence`
- `test_w3_072_setup_this_breakpoints`
- `test_w3_073_video_checkpoints`
- `test_w3_074_vesa_page_capture`
- `test_w3_075_startup_video_alignment`
- `test_w3_076_ah43_caller`
- `test_w3_077_int21_caller_capture`
- `test_w3_083_setup_continuation`
- `test_w3_089_address_writer_trace`
- `test_w3_091_ah4400_bx1_caller`
- `test_w3_095_psp_tail_capture`
- `test_w3_096_psp_tail_reconciliation`
- `test_w3_097_vesa_call_alignment`
- `test_w3_098_guard_output_capture`
- `test_w3_099_vesa_cap_suppression`
- `test_w3_100_targeted_vesa_capture`
- `test_w3_103_vesa_page_filter`
- `test_w3_104_vesa_page_callers`
- `test_w3_105_trace_frontier`
- `test_w3_106_draw_page_capture`
- `test_w3_107_main_transition`
- `test_w3_109_playintro_return_capture`
- `test_w3_132_smacker_alloc_static`
- `test_w3_135_allocator_return_reconcile`
- `test_w3_141_smacker_frontier`
- `test_w3_155_wscreen_refs`
- `test_w3_156_loader_callsite`
- `test_w3_171_wscreen_frame_boundary_samples`
- `test_w3_173_unsmack_capture`
- `test_w3_182_original_ax0300_capture`
- `test_w3_184_original_ax0300_window`
- `test_w3_188_b_screen_payload`
- `test_w3_197_ecdfollow_static`
- `test_w3_212_heap_alignment_capture`
- `test_w3_213_adjustment_capture`
- `test_w3_214_ax6300_pointer_capture`
- `test_w3_221_original_ax4400_bx1_alignment`
- `test_w3_226_stack_return_audit`
- `test_w3_230_gwerr_dispatch_capture`
- `test_w3_232_gwerr_ax4400_chronology`
- `test_w3_234_screen_copy_audit`
- `test_w3_236_chktty_original_capture`
- `test_w3_243_profile`
- `test_w3_246_cd_present_setup`
- `test_w3_248_bx1_native_original_audit`
- `test_w3_249_isatty_caller_pairing`
- `test_w3_250_tail_hook_reconciliation`
- `test_w3_251_entry_return_capture`
- `test_w3_252_timeline_alignment`
- `test_w3_254_mule_trace_compare`
- `test_w3_255_ah4400_bx1_reconcile`
- `test_w3_256_clang_prerequisite`
- `test_w3_257_staging_clang_build`
- `test_w3_258_oracle_guard_preflight`
- `test_w3_259_ah44_stack_sample`
- `test_w3_272_post_media_static_followthrough`
- `test_w3_273_post_media_symbol_context`
- `test_w3_274_second_play_smacker`
- `test_w3_275_second_smacker_call`
- `test_w3_276_play_smk_entry_comparison`
- `test_w3_277_play_smk_branch`
- `test_w3_278_play_smk_branch`
- `test_w3_282_replay_divergence`
- `test_w3_283_replay_timing_audit`
- `test_w3_284_smacker_dispatch_static`
- `test_w3_286_smacker_replay_reconciliation`
- `test_w3_287_smacker_timeout_audit`
- `test_w3_288_smacker_trigger_correction`
- `test_w3_289_smacker_later_callee_capture`
- `test_w3_291_ecd40_target_hit_capture`
- `test_w3_292_ecd40_run_reconciliation`
- `test_w3_295_video_pit_reconciliation`
- `test_w3_298_smacker_pit_capture`
- `test_w3_299_sound_hook_audit`
- `test_w3_300_activation_capture`

## Blocked modules (full list)

### needs evidence/ inputs (not published) (171)
`test_ah48_selector_reconciliation_work3`, `test_cd_present_gate_work3`, `test_critical_path_static_work1`, `test_crt_init_table_closure_work1`, `test_current_gate_projection_work3`, `test_dos4gw_low_targets_work2`, `test_dos_ah43_frontier_work2`, `test_dos_ah48_context_work3`, `test_dos_ah48_current_gate_work2`, `test_dos_ah48_selector_reuse_work2`, `test_dos_ah48_work2`, `test_dos_ax4400_runtime_work2`, `test_dos_cdrom_image_work2`, `test_dos_read_file`, `test_dos_services`, `test_dosbox_setup_game_oracle_work3`, `test_doshost_cue_filesystem_work2`, `test_dpmi0501_sparse_work2`, `test_dpmi_int2f_work2`, `test_dynamic_setup_game_callchain_work3`, `test_entry_mem_putc_integration_work1`, `test_fault_context_work2`, `test_first_divergence_lockstep_work1`, `test_getconfigs_contract_work3`, `test_getconfigs_eof_work3`, `test_getconfigs_file_audit_work3`, `test_getconfigs_staged_tree_work2`, `test_gp_ds_contract_work3`, `test_guest_boot`, `test_icall_slot_provenance_work3`, `test_main_gate_branch_audit_work3`, `test_map_overlap_ownership`, `test_mscdex_audio_status_work2`, `test_mscdex_audio_work2`, `test_mscdex_cue_metadata_work2`, `test_mscdex_cue_subchannel_work2`, `test_mscdex_inventory_reconcile_work3`, `test_mscdex_ioctl_buffer_work2`, `test_mscdex_ioctl_input_work2`, `test_mscdex_ioctl_status_geometry_work2`, `test_mscdex_ioctl_sub04_work2`, `test_mscdex_ioctl_sub0c_work2`, `test_mscdex_ioctl_track_work2`, `test_mscdex_ioctl_tracks_work2`, `test_mscdex_no_cd_vs_present_work3`, `test_mscdex_outer_return_work3`, `test_mscdex_packet_work2`, `test_mscdex_read_long_work2`, `test_mscdex_response_work2`, `test_mscdex_return_context_work3`, `test_native_adf95_caller_w1_064`, `test_native_ah44_bx1_callsite_work1`, `test_native_ah44_bx1_origin_work1`, `test_native_ax0501_strict_w1_063`, `test_native_ax4400_console_w1_056`, `test_native_crt_startup_capture_work1`, `test_native_dpmi_0501_frontier_work1`, `test_native_dpmi_success_path_work2`, `test_native_ds_compare_work3`, `test_native_es_ah49_frontier_work1`, `test_native_frontier_diagnostic_work2`, `test_native_main_argument_path_work1`, `test_native_mscdex_frontier`, `test_native_setup_config_frontier_work1`, `test_native_sound_ini_fixture_work1`, `test_native_startup_seed_parity_work3`, `test_native_stream_object_sample_work1`, `test_native_this_divergence_work1`, `test_native_w1_w2_replay_reconciliation_work1`, `test_native_w3_config_fixture_work2`, `test_nonmap_overlap_work3`, `test_original_ah44_handle2_frontier_work3`, `test_original_ah48_selector_work3`, `test_original_disc_iso_resource_work2`, `test_overlap_delta_work3`, `test_overlap_entry_redteam_work3`, `test_post_fnsave_corpus_audit_work3`, `test_runtime_bootstrap`, `test_setup_game_this_null_work1`, `test_setup_game_this_provenance_work3`, `test_startup_after_mscdex_work3`, `test_startup_ah48_bridge_current_work3`, `test_startup_ah48_sites_work3`, `test_startup_continuation_work3`, `test_startup_gate_classification_work3`, `test_startup_option_aliases_work3`, `test_startup_option_gate_work3`, `test_startup_runtime_current_work2`, `test_text_dat_gate_work3`, `test_text_dat_name_transform_work3`, `test_this_global_assembly_audit_work3`, `test_this_global_full_code_scan_work3`, `test_unicorn_probe`, `test_unicorn_services`, `test_verify_w1_050_pilot`, `test_video_frontier_work3`, `test_w1_035_dynamic_reach_audit_work1`, `test_w1_039_prior_segment_writes_work1`, `test_w1_066_environment_evidence`, `test_w1_066_environment_replay`, `test_w1_071_dpmi_ax6300_provider`, `test_w1_072_native_address_open`, `test_w1_073_handoff`, `test_w1_074_native_address_ax4400`, `test_w1_075_ah4400_first_mismatch`, `test_w1_086_bx1_context_reconciliation`, `test_w1_092_allocator_lifecycle`, `test_w1_093_dpmi_dos_boundary`, `test_w2_108_runtime_recovery`, `test_w2_109_ah4300_caller_reconciliation`, `test_w2_111_runtime_recovery`, `test_w2_112_runtime_recovery`, `test_w2_113_dpmi_vectors`, `test_w2_113_runtime_recovery`, `test_w2_115_dpmi0300_bridge`, `test_w2_115_runtime_recovery`, `test_w2_116_runtime_recovery`, `test_w2_117_evidence_fingerprint`, `test_w2_119_dos_handle_lifecycle`, `test_w2_119_runtime_recovery`, `test_w2_120_screen_copy_runtime_audit`, `test_w3_062_persisted_dosbox_mapping_audit`, `test_w3_069_ah43_capture_evidence`, `test_w3_079_ah44_bx1`, `test_w3_080_ah44_provenance`, `test_w3_081_original_ah44_caller`, `test_w3_082_handoff_boundary`, `test_w3_084_getconfigs_branch_compare`, `test_w3_085_handle5_lineage`, `test_w3_086_address_txt_provenance`, `test_w3_087_stream_startup_reconciliation`, `test_w3_088_address_writer`, `test_w3_092_ax4400_context_reconciliation`, `test_w3_093_ds_edx_sample`, `test_w3_094_post_vesa_call_alignment`, `test_w3_101_original_ah44_reconcile`, `test_w3_102_chktty_alignment`, `test_w3_108_playintro_continuation`, `test_w3_112_capture_frontier_audit`, `test_w3_120_post_media_successor`, `test_w3_128_b_screen_static_map`, `test_w3_150_screen_write_frontier`, `test_w3_159_wscreen_call_cfg`, `test_w3_162_dynrec_checkpoint_dispatch`, `test_w3_169_trace_reconcile`, `test_w3_170_screen_buffer_producer_audit`, `test_w3_172_smack_unsmack_dataflow`, `test_w3_174_unsmack_args_correction`, `test_w3_175_decoder_pointer_dataflow`, `test_w3_176_smack_callback_capture`, `test_w3_177_unsmack_dispatch`, `test_w3_178_unsmack_dispatch`, `test_w3_179_unsmack_dispatch`, `test_w3_180_smackinternal010`, `test_w3_181_smackinternal010_progress`, `test_w3_186_ah4400_bx1_provenance`, `test_w3_200_video_boundary_handoff`, `test_w3_201_bscreen_phase_audit`, `test_w3_204_ax0300_mapping_audit`, `test_w3_205_ax0300_fields_reconcile`, `test_w3_206_ah44_tail_reconcile`, `test_w3_215_anchor_reconciliation`, `test_w3_218_ah4400_tail_audit`, `test_w3_222_adjustment_checkpoint_audit`, `test_w3_228_gwerr_caller_capture`, `test_w3_229_gwerr_open_path_audit`, `test_w3_235_caller_context_audit`, `test_w3_240_capture_timeline_compare`, `test_w3_242_bx1_reconciliation`, `test_w3_268_playintro_frontier`, `test_w3_290_ecd40_stall_audit`

### needs third_party clone (92)
`test_dpmi_guest_map`, `test_dpmi_linear_lock`, `test_gw_recomp_trace`, `test_native_alloc_chain_generator_w1_062`, `test_native_dos_ah43_frontier_work2`, `test_native_dos_ah44_preflight_work2`, `test_native_dos_descriptors`, `test_native_dpmi_alloc`, `test_native_dpmi_dos_alloc`, `test_oracle_launch_policy`, `test_w1_091_guest_linear_memory`, `test_w2_083_lifecycle_harness`, `test_w2_110_ax4400_stream_classification`, `test_w2_111_ax4400_configured_console_info`, `test_w2_112_native_dpmi_0200`, `test_w2_116_dpmi6300_native_provider`, `test_w2_118_ax4400_bx5_lineage`, `test_w3_078_file_trace_filter`, `test_w3_110_hook_coverage_audit`, `test_w3_111_playintro_return_capture`, `test_w3_113_playintro_dynrec_coverage`, `test_w3_114_playintro_target_order`, `test_w3_115_play_smacker_branch`, `test_w3_116_play_smacker_state`, `test_w3_117_play_smacker_call_boundary`, `test_w3_121_reset_inputs_boundary`, `test_w3_122_post_reset_branches`, `test_w3_123_post_join_branch`, `test_w3_124_post_join_continuation`, `test_w3_125_lbmemoryalloc_boundary`, `test_w3_126_callback_coverage`, `test_w3_127_restart_coverage`, `test_w3_129_b_screen_capture`, `test_w3_131_game_entry_capture`, `test_w3_133_smacker_draw_route`, `test_w3_134_allocator_caller`, `test_w3_136_smacker_restart_coverage`, `test_w3_137_smacker_trace`, `test_w3_138_smacker_trace`, `test_w3_139_smacker_return_draw`, `test_w3_140_env_capture`, `test_w3_142_direct_smacker`, `test_w3_143_postopen_branch`, `test_w3_144_restart_coverage`, `test_w3_145_guarded_capture`, `test_w3_146_smack_transfer_capture`, `test_w3_147_smack_doframe_capture`, `test_w3_148_screen_swap_capture`, `test_w3_149_screen_swap_return`, `test_w3_151_screen_write_capture`, `test_w3_152_rep_copy_capture`, `test_w3_153_screen_samples`, `test_w3_154_source_destination_samples`, `test_w3_157_wscreen_load_to_copy`, `test_w3_158_loader_call_discriminator`, `test_w3_160_wscreen_gate_capture`, `test_w3_161_wscreen_instruction_boundary`, `test_w3_163_wscreen_link_redispatch`, `test_w3_164_sequential_dynrec_boundary`, `test_w3_167_wscreen_cached_span`, `test_w3_168_wscreen_gate_capture_eligibility`, `test_w3_191_ecd40_cache_probe`, `test_w3_192_ecd40_original_replay`, `test_w3_193_arm_ecd40_step`, `test_w3_194_ecd40_armed_replay`, `test_w3_195_ecd40_armed_replay`, `test_w3_196_ecd40_armed_replay`, `test_w3_198_ecd40_bounded_continuation`, `test_w3_199_ecd40_continuation_replay`, `test_w3_202_bscreen_free_sample`, `test_w3_203_bscreen_free_capture`, `test_w3_223_adjustment_dynrec_split`, `test_w3_224_ah4400_ordinal6_caller`, `test_w3_237_bx1_dynamic_pairing`, `test_w3_239_bx1_probe_window`, `test_w3_253_capture_flag_cache`, `test_w3_261_staging_video_source`, `test_w3_262_vga_present_capture`, `test_w3_263_vga_capture`, `test_w3_264_opengl_frame_capture`, `test_w3_265_opengl_gate`, `test_w3_266_full_frame_capture`, `test_w3_267_viewport_hash`, `test_w3_269_post_present_checkpoint`, `test_w3_271_after_media_frontier`, `test_w3_279_play_smk_step`, `test_w3_280_play_smk_step`, `test_w3_281_play_smk_gate`, `test_w3_285_smacker_callee_capture`, `test_w3_294_pit_port_capture`, `test_w3_main_capture_focused`, `test_w3_main_gate_trigger_synthetic`

### script-style; needs original files/evidence (45)
`test_authentic_lbdataload`, `test_authentic_memory_setup`, `test_authentic_titlescreen`, `test_building_action_0x14_ab`, `test_building_selection_and_panel`, `test_entry_closure_compile`, `test_entry_closure_native_link`, `test_frontier_snapshot_work2`, `test_guest_write_observer_coverage`, `test_icall_lift_work1`, `test_ifclevel_long_run`, `test_ifcoptions_roundtrip`, `test_ifctitle_creature_probe`, `test_ifctitle_plugin_first_load`, `test_ifctitle_plugin_load_at`, `test_interrupt_flag_roundtrip`, `test_lifted_interrupts`, `test_native_build_order_ab`, `test_native_command_tail`, `test_native_creature_plus17_frontier`, `test_native_dos4gw_large_file_read`, `test_native_dos_ah48_frontier_work2`, `test_native_dos_ah48_retry_work2`, `test_native_dos_ah49_frontier_work2`, `test_native_dos_callback`, `test_native_dos_streams`, `test_native_dos_time_query_work2`, `test_native_dos_vectors`, `test_native_dpmi_linear_alloc_frontier_work2`, `test_native_group_causality`, `test_native_guest_image`, `test_native_guest_tail_trap_work1`, `test_native_guest_trap_propagation_work1`, `test_native_guest_trap_state_work1`, `test_native_ifctitle_ctor`, `test_null_ds_read_diagnostic`, `test_oracle_guard`, `test_overnight_phase1_player_snapshot`, `test_overnight_soak_3000`, `test_partial_graphics_lift`, `test_partial_graphics_pixels`, `test_rebased_guest_icall_dispatch`, `test_recompiled_file_open`, `test_recompiled_iftitle_pipeline`, `test_snapshot_fast_resume_parity`

### needs pcrecomp lifter dependency (21)
`test_authentic_resource_callback_init`, `test_authentic_title_loadall`, `test_conditional_tail_lift_work1`, `test_fnsave`, `test_lift32_overlapping_block_fallthrough`, `test_lifter_bsr`, `test_lifter_integer_width_semantics`, `test_lifter_pushf`, `test_lifter_sar_signed_width`, `test_memory_access_diagnostic`, `test_rationalalloc_core_validation_work1`, `test_segment_access_bounds`, `test_segment_bases`, `test_segment_load_audit_work1`, `test_segment_string_bounds`, `test_selector_slot_roundtrip`, `test_title_fx_menu_crosswalk`, `test_w1_087_port_io_lift`, `test_w1_088_generated_port_io_integration`, `test_w1_100_dynamic_ret_thunk`, `test_x87_fninit_lift`

### needs unpublished internal task-queue files (13)
`test_autopilot_v1`, `test_post_mscdex_gate_metrics_work3`, `test_project_state_native_frontier_work3`, `test_taskq_concurrency`, `test_taskq_release`, `test_w2_121_autopilot_files_owned_recovery`, `test_w2_122_pit8254_runtime`, `test_w2_123_port_io_runtime`, `test_w3_183_int31_hook_boundary`, `test_w3_219_dashboard_audit`, `test_w3_245_current_gate_projection`, `test_w3_247_current_cd_gate_projection`, `test_w3_293_pit_port_capture`

### needs DOSBox-X oracle sandbox (11)
`test_w1_090_ax0501_sequence`, `test_w3_060_ah44_handle2_contract`, `test_w3_166_wscreen_checkpoint_coverage`, `test_w3_187_post_dpmi_screen_path`, `test_w3_189_wscreen_temporal_reconcile`, `test_w3_190_smackinternal_hook_gap`, `test_w3_225_ah4400_static_audit`, `test_w3_227_ah44_divergence_chronology`, `test_w3_270_post_present_static_frontier`, `test_w3_296_pit_routine_static`, `test_w3_297_sound_gate_static`

### needs work/ artifacts (not published) (7)
`test_rea_le_pe_carrier`, `test_w1_079_native_ax4400_created_file`, `test_w1_080_native_ax4400_active_file`, `test_w1_081_native_ah40_active_file`, `test_w1_083_config_read_mapping`, `test_w1_084_native_ah40_continuation`, `test_w1_085_ah4400_caller_provenance`

### needs generated build outputs (3)
`test_lifted_cpu_context`, `test_main_post_setup_frontier_work3`, `test_video_closure_preflight_work1`

### needs original game files (1)
`test_w3_241_isatty_static_caller`

