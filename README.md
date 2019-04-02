### p4tests

Each folder refers to a different algorithm found in the literature and contains a (start of) its implementation in p4. 
Complimentary scripts accompany them in python or perl. 

Pretty much the entire thing was made re-using the p4 tutorials; the topology, jsons and commands files are still there, mostly untouched. This also means the back end is the same.

To run an algorithm, use `make run`. Don't forget to clean up afterwards with `make clean`. 

Most algorithms involve a given data structure stored in the switches' stateful memory. They can be consulted from CLI with `simple_switch_CLI --thrift-port=[PORT]` while mininet runs.

arithmetic uses calc.py instead as it is a touched up calculator exercise from the p4 tutorials. use `h1 python calc.py` from the mininet CLI to get the prompt.

Further details can be found in comments & READMEs.
