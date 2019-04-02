#### TODOS 

Use recirculates in place of dual instantiations?

#### Why we duplicate the tables 

In v1model, one restriction is that the same table may not be called more than once in an Ingress or Egress control.

The exact error message when attempting to use the same table more than once in the same Ingress or Egress control is  

>`Program cannot be implemented on this target since there it contains a path from table MyIngress.log\_val back to itself`

As we use 

>`a*[/]b ~ exp(log(a)+[-]log(b))`  

for these approximations, we need two instances of the log table so we can call them both in the same control when we invoke the multiplication or division approximations.

#### Summary 

The main parameters to tweak for tests are found in table\_fill.pl to adjust the tables serving to approximate mult/div

arithmetic.p4 is a modified version of the calculator exercise available from the P4 tutorials. 

In short, upon build $make run, three hosts 10.0.X.X (X in 1,2,3) are instantiated, each respectivelly linked to one of three switches s1, s2, s3

From the mininet prompt, you call the calc.py script by one of the hosts with 

`hX python calc.py`

This changes the prompt to the calc.py's interactive CLI, which lets you use one of available operations by parsing messages of the form 

`Integer Operator Integer`

The legal operators are: `+ - & | ^ * /`

Because v1model objects -and p4 implementations also might- to reusing tables, and the arithmetic tables used to approximate the multiplication/division loaded are rather large, only one of the last two operation is loaded by default for faster build. You can change this in arithmetic.p4

#### Why do we use tables to approximate multiplication/division? 

The p4 language does NOT support floating point arithmetic, so we need to approximate these operations. 

We are here approximating them with 

`A*B ~ exp ( log(A)+log(B) )`  
`A/B ~ exp ( log(A)-log(B) )` 

The tables are approximated with a limited number of entries with the script table\_fill.pl and saved in the tables/ folder.

The formulas used is taken from the "Evaulating Flexible Packet Processing" paper.

Succinctly, exp is an exact table since it has an exp gradient. However, log can use less entries, by only checking entries of the form 
`0^n++1++(0|1)^min(m-1,N-n-1)++[REMAINING MASKED BITS]`
for numbers encoded in N bits, 0 <= n < N

Some more details can be found in the introductory comment of table\_fill.pl


