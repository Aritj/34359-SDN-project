# 34359-SDN-project

![image](https://github.com/user-attachments/assets/b50acd16-f57d-4db8-a156-f2a5ec3a80b3)


## BUILD PROJECT
```
mvn clean install
onos-app localhost install target/optical-bypass-1.0-SNAPSHOT.oar
```

## START CLEAN INSTANCE OF ONOS (WINDOW 1)
```
cd ~/onos && bazel run onos-local -- clean
```

## SIMULATE NETWORK TOPOLOGY USING MININET (WINDOW 2)
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

## CLEANUP
```
sudo mn -c
```
