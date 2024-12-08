# 34359-SDN-project

## BUILD PROJECT
```
mvn clean install
onos-app localhost install target/optical-bypass-1.0-SNAPSHOT.oar
```

## START MININET (WINDOW 1)
```
sudo python network_topology.py
```

## START ONOS (WINDOW 2)
```
cd ~/onos && bazel run onos-local -- clean
```

## ATTACH TO ONOS TERMINAL (WINDOW 3)
```
onos localhost
```

## USEFUL ONOS COMMANDS
```
onos> app activate org.onosproject.fwd
onos> app deactivate org.onosproject.fwd
onos> app uninstall org.student.opticalbypass
onos> app activate org.student.opticalbypass
onos> app deactivate org.student.opticalbypass 
onos> logout
```
