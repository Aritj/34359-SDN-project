# 34359-SDN-project

## START MININET
sudo python [file.py]

## START ONOS
cd ~/onos
bazel run onos-local -- clean

## ATTACH TO ONOS TERMINAL
onos localhost
app activate org.student.opticalbypass
app deactivate org.student.opticalbypass 

pi
onos-app localhost install target/optical-bypass-1.0-SNAPSHOT.oar 


## onos localhost
onos> app activate org.onosproject.fwd
onos> app deactivate org.onosproject.fwd
onos> app uninstall org.student.opticalbypass
onos> logout
