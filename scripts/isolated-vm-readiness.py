#!/usr/bin/env python3
"""CI-only, no-NIC Linux VM boot/reboot readiness; never peer/TLS acceptance."""
from pathlib import Path
import argparse,gzip,hashlib,json,os,re,selectors,signal,struct,subprocess,tempfile,time

def require(value,message):
    if not value:raise RuntimeError(message)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def command(args,cwd=None,timeout=180,limit=2*1024*1024,environment=None):
    # Keep a root-owned timeout supervisor around the only privileged operation.
    if args[:2]==['sudo','-n']:
        args=args[:2]+['timeout','--signal=TERM','--kill-after=5s',str(timeout)]+args[2:]
        timeout+=15
    process=subprocess.Popen(args,cwd=cwd,env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    selector=selectors.DefaultSelector();output=bytearray();end=time.monotonic()+timeout;failure=None
    try:
        selector.register(process.stdout,selectors.EVENT_READ)
        while True:
            if time.monotonic()>=end:failure='Owned package/tool command timed out';break
            if selector.select(min(0.2,max(0,end-time.monotonic()))):
                chunk=os.read(process.stdout.fileno(),65536)
                if not chunk:
                    try:process.wait(timeout=max(0.01,min(5,end-time.monotonic())))
                    except subprocess.TimeoutExpired:failure='Owned package/tool command timed out after output closed'
                    break
                if len(output)+len(chunk)>limit:failure='Owned package/tool output budget exceeded';break
                output+=chunk
            elif process.poll() is not None:break
    finally:
        if failure or process.poll() is None:
            if args[0]=='sudo':
                cleanup=subprocess.run(['sudo','-n','/bin/kill','-KILL','--',f'-{process.pid}'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
                require(cleanup.returncode==0 or process.poll() is not None,'Owned privileged command cleanup uncertain; disposable runner teardown required')
            else:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
        try:result=process.wait(timeout=5)
        except subprocess.TimeoutExpired:raise RuntimeError('Owned command cleanup uncertain; disposable runner teardown required') from None
        finally:selector.close();process.stdout.close()
    require(failure is None,failure)
    require(result==0,'Recognized package/tool command failed: '+str(args[0])+' exit='+str(result))
    return output.decode('utf-8')

def cpio_image(busybox):
    """Write only fixed newc paths; device metadata exists inside the archive only."""
    init=b'''#!/bin/sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec </dev/ttyS0 >/dev/ttyS0 2>&1
devdrop_guest=unknown
for devdrop_word in $(cat /proc/cmdline); do
 case "$devdrop_word" in devdrop_guest=*) devdrop_guest=${devdrop_word#*=};; esac
done
case "$devdrop_guest" in devdrop-a|devdrop-b) ;; *) poweroff -f;; esac
devdrop_kernel=$(uname -r)
devdrop_boot=$(sha256sum /proc/sys/kernel/random/boot_id | cut -d' ' -f1)
devdrop_interfaces=$(ls /sys/class/net | tr '\\n' ' ')
printf 'DEVDROP_VM_READY {"schema":"devdrop-nicless-vm/v1","guest":"%s","kernel":"%s","boot_id_sha256":"%s","interfaces":"%s"}\\n' "$devdrop_guest" "$devdrop_kernel" "$devdrop_boot" "$devdrop_interfaces"
while IFS= read -r devdrop_command; do
 case "$devdrop_command" in
  reboot) sync; reboot -f;;
  poweroff) sync; poweroff -f;;
  *) echo DEVDROP_CONTROL_REFUSED;;
 esac
done
poweroff -f
'''
    entries=[('.',0o040755,b'',0,0),('bin',0o040755,b'',0,0),('dev',0o040755,b'',0,0),('proc',0o040755,b'',0,0),('sys',0o040755,b'',0,0),('tmp',0o041777,b'',0,0),('dev/console',0o020600,b'',5,1),('bin/busybox',0o100755,Path(busybox).read_bytes(),0,0),('bin/sh',0o120777,b'busybox',0,0),('init',0o100755,init,0,0),('TRAILER!!!',0,b'',0,0)]
    data=bytearray()
    for inode,(name,mode,body,major,minor) in enumerate(entries,1):
        require(name=='.' or not(name.startswith('/') or '..' in name.split('/')),'Archive path escaped fixed fixture namespace')
        filename=name.encode()+b'\0';fields=[inode,mode,0,0,1,0,len(body),0,0,major,minor,len(filename),0]
        data+=b'070701'+b''.join(f'{value:08x}'.encode() for value in fields)+filename
        data+=b'\0'*((-len(data))%4);data+=body;data+=b'\0'*((-len(data))%4)
    return gzip.compress(bytes(data),mtime=0)

def static_elf(path):
    data=Path(path).read_bytes();require(data[:6]==b'\x7fELF\x02\x01','BusyBox must be known little-endian ELF64')
    off=struct.unpack_from('<Q',data,32)[0];size,count=struct.unpack_from('<HH',data,54)
    require(size>=56 and off+size*count<=len(data),'Invalid ELF program table')
    require(all(struct.unpack_from('<I',data,off+i*size)[0]!=3 for i in range(count)),'Guest BusyBox must be statically linked')

def elf_interpreter(path):
    data=Path(path).read_bytes();require(data[:6]==b'\x7fELF\x02\x01','QEMU must be known little-endian ELF64')
    off=struct.unpack_from('<Q',data,32)[0];size,count=struct.unpack_from('<HH',data,54)
    require(size>=56 and off+size*count<=len(data),'Invalid QEMU ELF program table')
    for i in range(count):
        at=off+i*size
        if struct.unpack_from('<I',data,at)[0]==3:
            start=struct.unpack_from('<Q',data,at+8)[0];length=struct.unpack_from('<Q',data,at+32)[0]
            require(length<256 and start+length<=len(data),'Invalid ELF interpreter')
            loader=Path(data[start:start+length].rstrip(b'\0').decode())
            require(loader.is_absolute() and loader.is_file() and loader.name.startswith('ld-linux'),'Unsupported system ELF loader')
            return loader
    raise RuntimeError('Expected standard dynamic QEMU loader')

def qemu_args(binary,firmware,kernel,initrd,name,data_dir):
    require(name in ('devdrop-a','devdrop-b'),'Unknown generated guest identity')
    return [str(binary),'-name',name,'-machine','pc,dump-guest-core=off,mem-merge=off','-accel','tcg,thread=multi','-cpu','max','-smp','1','-m','512','-nodefaults','-no-user-config','-display','none','-monitor','none','-serial','stdio','-nic','none','-L',str(data_dir),'-bios',str(firmware),'-kernel',str(kernel),'-initrd',str(initrd),'-append',f'console=ttyS0 rdinit=/init panic=0 devdrop_guest={name}']

class Guest:
    def __init__(self,args,environment):
        self.proc=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=environment)
        try:
            self.selector=selectors.DefaultSelector();self.selector.register(self.proc.stdout,selectors.EVENT_READ);self.buffer=b'';self.total=0;self.boot_signatures=[]
        except Exception:
            self.proc.kill();self.proc.wait(timeout=5)
            for stream in (self.proc.stdin,self.proc.stdout):
                if stream:stream.close()
            raise
    def ready(self,timeout=90):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            while b'\n' in self.buffer:
                line,self.buffer=self.buffer.split(b'\n',1)
                # Only fixed diagnostic categories leave this blank guest. No
                # raw console, memory addresses, environment or guest data.
                for signature in (b'Could not load option rom',b'could not load PC BIOS',b'Linux version',b'Kernel panic',b'Failed to execute /init',b'Run /init',b'Unpacking initramfs',b'Initramfs unpacking failed',b'No working init found',b'Unable to mount root',b'Waiting for root device',b'random: crng init done'):
                    label=signature.decode('ascii')
                    if signature in line and label not in self.boot_signatures:self.boot_signatures.append(label)
                if b'DEVDROP_VM_READY ' in line:
                    record=json.loads(line.split(b'DEVDROP_VM_READY ',1)[1].strip())
                    require(record['schema']=='devdrop-nicless-vm/v1','Wrong guest report schema')
                    require(record['guest'] in ('devdrop-a','devdrop-b') and re.fullmatch('[0-9a-f]{64}',record['boot_id_sha256']),'Invalid bounded guest report')
                    require(record['interfaces'].strip()=='lo','A guest unexpectedly has a non-loopback interface')
                    require(re.fullmatch('[A-Za-z0-9._+-]{1,128}',record['kernel']),'Invalid kernel report')
                    return record
            require(self.proc.poll() is None,'No-NIC guest exited before readiness')
            if self.selector.select(min(1,max(0,end-time.monotonic()))):
                chunk=os.read(self.proc.stdout.fileno(),65536);require(bool(chunk),'No-NIC guest console closed')
                self.total+=len(chunk);require(self.total<=2*1024*1024,'Guest console exceeded its metadata budget');self.buffer+=chunk
        raise RuntimeError('No-NIC guest readiness timed out; console_bytes='+str(self.total)+'; boot_signatures='+json.dumps(self.boot_signatures))
    def send(self,action):
        require(action in ('reboot','poweroff'),'Unknown guest control action');self.proc.stdin.write((action+'\n').encode());self.proc.stdin.flush()
    def close(self):
        if self.proc.poll() is None:
            try:self.send('poweroff');self.proc.wait(timeout=5)
            except (OSError,subprocess.TimeoutExpired):self.proc.kill();self.proc.wait(timeout=5)
        self.selector.close()
        for stream in (self.proc.stdin,self.proc.stdout):
            if stream:stream.close()


def run(output):
    require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted' and os.environ.get('DEVDROP_PUBLIC_REPOSITORY')=='true','This helper may execute only on an approved public hosted CI fixture')
    require(os.environ.get('GITHUB_REPOSITORY')=='Rickythegreat1/dropdev' and os.environ.get('GITHUB_JOB')=='no_nic_guests','Wrong repository or CI job')
    require(os.uname().machine=='x86_64','Only the reviewed x86_64 fixture is supported')
    runner_temp=Path(os.environ['RUNNER_TEMP']).resolve(strict=True);output=Path(output).absolute()
    require(str(runner_temp).startswith('/home/runner/work/') and output==runner_temp/'devdrop-nicless-vm-readiness.json' and not output.exists() and not output.is_symlink(),'Expected a new exact hosted readiness report path')
    status_before=sha('/var/lib/dpkg/status')
    with tempfile.TemporaryDirectory(prefix='devdrop-vm-readiness-',dir=os.environ['RUNNER_TEMP']) as scratch:
        root=Path(scratch);root.chmod(0o755);debs=root/'debs';debs.mkdir(mode=0o755);tools=root/'tools';tools.mkdir();kernel_dir=root/'kernel';kernel_dir.mkdir()
        # Normal signed configured APT; no skipped config/authentication and no install/postinst.
        command(['sudo','-n','apt-get','update'],timeout=240)
        simulation=command(['apt-get','--simulate','--no-install-recommends','--assume-yes','install','qemu-system-x86','busybox-static'],timeout=60)
        requested={name:version for name,version in re.findall(r'^Inst ([a-z0-9.+:-]+)(?: \[[^\]]+\])? \(([^ ]+)',simulation,re.MULTILINE)}
        for package in ['qemu-system-x86','qemu-system-common','qemu-system-data','seabios','busybox-static']:
            metadata=command(['apt-cache','show','--no-all-versions',package])
            candidate=re.search(r'^Version: (\S+)$',metadata,re.MULTILINE)
            require(candidate is not None,'Official package candidate missing')
            requested.setdefault(package,candidate.group(1))
        require(0<len(requested)<=128,'Unexpected package resolution size')
        command(['apt-get','download']+[f'{name}={version}' for name,version in requested.items()],cwd=debs,timeout=300)
        packages=[]
        for deb in sorted(debs.glob('*.deb')):
            package=command(['dpkg-deb','--field',str(deb),'Package']).strip();version=command(['dpkg-deb','--field',str(deb),'Version']).strip()
            require(re.fullmatch('[a-z0-9.+-]+',package) and len(version)<128,'Invalid package metadata')
            packages.append({'package':package,'version':version,'sha256':sha(deb)})
            command(['dpkg-deb','--extract',str(deb),str(tools)])
        dependencies=command(['apt-cache','depends','linux-image-virtual'])
        candidates=re.findall(r'Depends:\s+(linux-image-[0-9][a-zA-Z0-9.+-]+)',dependencies)
        require(len(set(candidates))==1,'Official virtual-kernel package could not be resolved uniquely')
        kernel_package=candidates[0];command(['apt-get','download',kernel_package],cwd=kernel_dir,timeout=240)
        kernel_debs=list(kernel_dir.glob('*.deb'));require(len(kernel_debs)==1,'Expected one official kernel package')
        kernel_deb=kernel_debs[0];kernel_meta={'package':kernel_package,'version':command(['dpkg-deb','--field',str(kernel_deb),'Version']).strip(),'sha256':sha(kernel_deb)}
        extract=kernel_dir/'extracted';extract.mkdir();command(['dpkg-deb','--extract',str(kernel_deb),str(extract)])
        kernels=list((extract/'boot').glob('vmlinuz-*'));require(len(kernels)==1,'Expected exactly one extracted official kernel')
        busybox=tools/'bin/busybox'
        if not busybox.is_file():busybox=tools/'usr/bin/busybox'
        static_elf(busybox)
        initrd=root/'initrd.cpio.gz';initrd.write_bytes(cpio_image(busybox))
        binary=tools/'usr/bin/qemu-system-x86_64';require(binary.is_file(),'Extracted official QEMU binary missing')
        bios=tools/'usr/share/seabios/bios-256k.bin';require(bios.is_file(),'Extracted official BIOS missing')
        data_dir=tools/'usr/share/qemu';require((data_dir/'linuxboot_dma.bin').is_file(),'Official QEMU kernel loader ROM missing')
        environment=os.environ.copy()
        # Task-local libraries only; inherited proxies/CA/security configuration stay intact.
        paths=[tools/'usr/lib/x86_64-linux-gnu',tools/'lib/x86_64-linux-gnu',tools/'usr/lib',tools/'lib']
        environment['QEMU_MODULE_DIR']=str(tools/'usr/lib/x86_64-linux-gnu/qemu')
        prefix=[str(elf_interpreter(binary)),'--library-path',':'.join(map(str,paths))]
        version=command(prefix+[str(binary),'--version'],environment=environment,timeout=10,limit=4096)
        guests=[]
        try:
            for name in ('devdrop-a','devdrop-b'):guests.append(Guest(prefix+qemu_args(binary,bios,kernels[0],initrd,name,data_dir),environment))
            first=[guest.ready() for guest in guests]
            require(first[0]['guest']=='devdrop-a' and first[1]['guest']=='devdrop-b' and first[0]['boot_id_sha256']!=first[1]['boot_id_sha256'],'Independent guest identities did not verify')
            receiver_pid=guests[1].proc.pid;guests[1].send('reboot');reboot=guests[1].ready()
            require(guests[1].proc.pid==receiver_pid and reboot['guest']=='devdrop-b' and reboot['boot_id_sha256']!=first[1]['boot_id_sha256'],'Actual same-emulator guest reboot did not verify')
            record={'schema':'devdrop-nicless-vm-readiness/v1','commit':os.environ['GITHUB_SHA'],'workflow_run_id':os.environ['GITHUB_RUN_ID'],'job_id':os.environ['GITHUB_JOB'],'host_kernel':os.uname().release,'accelerator':'QEMU TCG software emulation','qemu_version':version.splitlines()[0],'host_count':1,'guest_count':2,'guest_vcpus_each':1,'guest_ram_mib_each':512,'nics_each':0,'tls_started':False,'cross_vm_tls_acceptance':False,'peer_queue_reboot_recovery':False,'persistent_credentials':False,'package_mode':'signed APT simulation+unprivileged download, task-local extraction; no maintainer scripts or system install','packages':packages,'kernel_package':kernel_meta,'kernel_sha256':sha(kernels[0]),'initrd_sha256':sha(initrd),'busybox_sha256':sha(busybox),'guest_initial_boots':first,'receiver_reboot':reboot,'checks':[{'name':'two_actual_independent_linux_guests_no_nics','passed':True},{'name':'guest_kernel_reboot_new_boot_identity_same_emulator','passed':True}]}
        finally:
            cleanup_errors=[]
            for guest in guests:
                try:guest.close()
                except Exception:cleanup_errors.append(True)
            require(not cleanup_errors,'Generated guest cleanup failed; disposable runner teardown required')
        require(sha('/var/lib/dpkg/status')==status_before,'Download-only setup unexpectedly changed installed package state')
        record['checks'].append({'name':'host_installed_package_state_unchanged','passed':True})
        with os.fdopen(os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w') as report:report.write(json.dumps(record,indent=2)+'\n')
        print('NICLESS_VM_READINESS_EVIDENCE='+json.dumps(record,sort_keys=True))
    return 0

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args()
    try:raise SystemExit(run(args.output))
    except Exception as error:
        print(json.dumps({'schema':'devdrop-nicless-vm-readiness-failure/v1','kind':type(error).__name__,'message':str(error) if isinstance(error,RuntimeError) else 'Recognized disposable readiness step failed; no private network was enabled.','cross_vm_tls_acceptance':False}));raise SystemExit(1)
