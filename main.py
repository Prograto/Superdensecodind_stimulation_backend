from qiskit import QuantumCircuit

qc = QuantumCircuit(2, 2)
qc.h(0)
qc.cx(0,1)
qc.measure([0,1],[0,1])

# Draw the circuit
print(qc.draw(output='text'))
