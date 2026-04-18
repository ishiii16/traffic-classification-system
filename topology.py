from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel


def create_topology():
    net = Mininet(controller=RemoteController)

    # Add remote Ryu controller
    controller = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    # Add switches
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')

    # Add hosts
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    h3 = net.addHost('h3', ip='10.0.0.3')
    h4 = net.addHost('h4', ip='10.0.0.4')

    # Add links
    net.addLink(s1, s2)
    net.addLink(s1, s3)
    net.addLink(s2, h1)
    net.addLink(s2, h2)
    net.addLink(s3, h3)
    net.addLink(s3, h4)

    net.start()
    print("Network started. Use CLI to test.")
    print("Try: h1 ping h3   or   h1 ping h4")
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
