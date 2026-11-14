from __future__ import annotations
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TRACE=ROOT/'build/dosboxx_oracle/C/W3_184_ORIGINAL_AX0300_WINDOW_20261009_01.jsonl'
OUT=ROOT/'evidence/w3_187_post_dpmi_screen_path.json'

def audit(rows=None):
 raw=TRACE.read_bytes()
 if rows is None:
  rows=[json.loads(line) for line in raw.splitlines() if line]
 def one(name):
  return next((r for r in rows if r.get('checkpoint')==name),None)
 def link(r): return int(r.get('link_va',-1)) if r else None
 entry=one('W3_182_DPMI0300_ENTRY'); ret=one('W3_182_DPMI0300_RETURN')
 main=one('MAIN_ENTRY_CHECKPOINT'); setup=one('SETUP_GAME_ENTRY')
 intro=one('PLAYINTRO_ENTRY'); mode=one('VIDEO_VESA_MODE_CALLSITE') or one('VIDEO_SCREEN_SETUP_ANY_MODE')
 fb_after=one('VIDEO_FRAMEBUFFER_ASSIGN_AFTER')
 smack=one('W3_142_SMACKDOFRAME_ENTRY')
 bscreen=one('W3_129_B_SCREEN_POST_STORE'); free=one('W3_129_MEMORY_FREE_ENTRY')
 require=[entry,ret,main,setup,intro,fb_after,smack,bscreen,free]
 if any(x is None for x in require): raise ValueError('required checkpoint missing')
 bscreen_sample_fields=[k for k in bscreen if 'buffer' in k and ('hex' in k or 'sample_bytes' in k)]
 # This event's *_sample_valid field only validates reading the B_SCREEN global itself.
 content_sample=any(k in bscreen for k in ('w3_129_buffer_sample_hex','pixel_data_hex','framebuffer_bytes_hex'))
 return {
  'schema':'w3-187-post-dpmi-screen-path/v1','task':'W3-187',
  'trace':{'path':str(TRACE.relative_to(ROOT)).replace('\\','/'),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'events':len(rows)},
  'ordered_checkpoints':[
   {'sequence':r['sequence'],'name':r['checkpoint'],'link_va':hex(link(r)),'eip':hex(int(r['eip']))}
   for r in sorted((entry,ret,main,setup,intro,fb_after,smack,bscreen,free), key=lambda x: x['sequence'])
  ],
  'mapping':{'main_code_rebase':hex(int(main['eip'])-link(main)),'dpmi_mapping_consistent':int(entry['eip'])-0x1eb000==0xbc765 and int(ret['eip'])-0x1eb000==0xbc767},
  'video':{
   'first_framebuffer_assign_sequence':one('VIDEO_FRAMEBUFFER_ASSIGN_BEFORE').get('sequence') if one('VIDEO_FRAMEBUFFER_ASSIGN_BEFORE') else None,
   'framebuffer_assign_after':{'sequence':fb_after['sequence'],'eax':hex(int(fb_after['eax']))},
   'vesa_mode_callsite':{'sequence':mode['sequence'],'link_va':hex(link(mode)),'eax':hex(int(mode['eax']))} if mode else None,
   'smackdoframe_reached':True,'playintro_reached':True,
  },
  'b_screen':{
   'store_sequence':bscreen['sequence'],'data_rebase':hex(int(bscreen['w3_129_data_rebase'])),
   'global_link_offset':hex(0x114ca0),'global_read_valid':bscreen['w3_129_b_screen_sample_valid'],
   'buffer_pointer':hex(int(bscreen['w3_129_b_screen_value'])),
   'later_matching_free_sequence':free['sequence'],'free_eax':hex(int(free['eax'])),
   'free_matches_pointer':int(free['eax'])==int(bscreen['w3_129_b_screen_value']),
   'pointed_buffer_content_sample_present':content_sample,
   'global_sample_is_not_buffer_payload':True,
   'buffer_sample_field_names_found':bscreen_sample_fields,
  },
  'claims':{'original_post_dpmi_continuation_observed':True,'video_setup_and_smacker_path_observed':True,'pixel_payload_observed':False,'visible_frame_confirmed':False,'menu_confirmed':False},
  'next_bounded_observation':{'checkpoint':'link VA 0x92B87, immediately after B_SCREEN global store and before matching free at 0x92030','sample':'up to 64 bytes at the measured B_SCREEN pointer 0x8B03C8, only if allocation bounds and descriptor/physical bounds are revalidated at runtime','purpose':'determine whether the allocated buffer contains nonzero payload; this alone would not establish visible presentation'},
  'guard_context':'Evidence reuses the W3-184 original Staging replay through oracle_guard; this audit ran no emulator and made no guest writes.'
 }

if __name__=='__main__': OUT.write_text(json.dumps(audit(),indent=2)+'\\n',encoding='utf-8')

