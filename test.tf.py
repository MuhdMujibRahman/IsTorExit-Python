from terraformpy import Variable

Variable(
    'tor_exit_ip_list',
    default = ['127.0.0.1', '127.0.0.2']
)