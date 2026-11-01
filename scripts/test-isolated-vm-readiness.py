import importlib.util,gzip,os,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('vm_readiness',Path(__file__).with_name('isolated-vm-readiness.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ReadinessSafety(unittest.TestCase):
 def test_guest_command_has_no_nic_monitor_display_or_host_share(self):
  args=m.qemu_args('/fixture/qemu','/fixture/bios','/fixture/kernel','/fixture/initrd','devdrop-a')
  self.assertEqual(args[args.index('-nic')+1],'none');self.assertEqual(args[args.index('-monitor')+1],'none');self.assertEqual(args[args.index('-display')+1],'none')
  self.assertNotIn('-netdev',args);self.assertNotIn('-virtfs',args);self.assertNotIn('-drive',args);self.assertIn('tcg,thread=multi',args)
  with self.assertRaises(RuntimeError):m.qemu_args('q','b','k','i','unknown -nic user')
 def test_cpio_contains_only_fixed_guest_fixture_and_no_network_setup(self):
  with tempfile.TemporaryDirectory() as root:
   p=Path(root)/'known-busybox';p.write_bytes(b'generated binary placeholder');data=gzip.decompress(m.cpio_image(p));names=[];offset=0;init=None
   while offset<len(data):
    self.assertEqual(data[offset:offset+6],b'070701');values=[int(data[offset+6+i*8:offset+14+i*8],16) for i in range(13)];length=values[6];name_length=values[11];offset+=110;name=data[offset:offset+name_length-1].decode();names.append(name);offset+=name_length;offset=(offset+3)&~3;body=data[offset:offset+length];offset+=length;offset=(offset+3)&~3
    if name=='init':init=body
    if name=='TRAILER!!!':break
   self.assertEqual(set(names),{'.','bin','dev','proc','sys','tmp','dev/console','bin/busybox','bin/sh','init','TRAILER!!!'})
   self.assertIsNotNone(init);self.assertNotIn(b'ifconfig',init);self.assertNotIn(b'ip addr',init);self.assertNotIn(b'ssh',init);self.assertNotIn(b'PRIVATE KEY',init)
 def test_local_or_private_ci_refused_before_commands(self):
  with patch.dict(os.environ,{'GITHUB_ACTIONS':'false','RUNNER_ENVIRONMENT':'github-hosted','DEVDROP_PUBLIC_REPOSITORY':'true'}),patch.object(m,'command') as command:
   with self.assertRaises(RuntimeError):m.run('/tmp/not-created-vm-proof.json')
   command.assert_not_called()
 def test_command_output_budget_kills_only_owned_group(self):
  with self.assertRaisesRegex(RuntimeError,'output budget'):
   m.command([sys.executable,'-c','print("x"*8192)'],limit=1024,timeout=5)
 def test_command_timeout_is_bounded_and_regular_output_works(self):
  self.assertEqual(m.command([sys.executable,'-c','print("fixture")'],limit=128,timeout=5),'fixture\n')
  start=time.monotonic()
  with self.assertRaisesRegex(RuntimeError,'timed out'):
   m.command([sys.executable,'-c','import time;time.sleep(30)'],timeout=0.1)
  self.assertLess(time.monotonic()-start,5)
if __name__=='__main__':unittest.main()
