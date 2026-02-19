import os

def copy_between_hosts(src_host, src_path, dst_host, dst_path):
    tmp_path = os.path.join(os.getcwd(), "tmp_copy_between_hosts_file")
    src_host.wait_for_file(src_path)
    src_host.copy_from_vm(src_path, tmp_path)
    if not os.path.exists(tmp_path):
      raise Exception(f"Transfer failed: {tmp_path} was not created on the host!")
    dst_host.copy_from_host(tmp_path, dst_path)
    os.unlink(tmp_path)
