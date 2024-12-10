# 34359-SDN-project

## BUILD PROJECT
```
mvn clean install
onos-app localhost install target/optical-bypass-1.0-SNAPSHOT.oar
```

## START ONOS (WINDOW 1)
```
cd ~/onos && bazel run onos-local -- clean
```

## START MININET (WINDOW 2)
```
sudo python optical_bypass.py
mininet> h01 ping h02
mininet> h01 ping h11
mininet> h01 curl h11
mininet> xterm h01 h11 h21 h31
```


## ATTACH TO ONOS TERMINAL AND VIEW LOGS (WINDOW 3)
```
onos localhost
onos> log:tail
```

## ATTACH TO ONOS TERMINAL AND CONFIGURE FORWARDING APPLICATIONS (WINDOW 4)
```
onos localhost
onos> app deactivate org.onosproject.fwd
onos> app activate org.student.opticalbypass
```

## USEFUL ONOS COMMANDS
```
onos> app uninstall org.student.opticalbypass
onos> logout
```
