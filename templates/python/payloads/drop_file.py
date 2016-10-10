loader="""
file_drop_output = "file_drop_output" + str(r"{0}")

with open(file_drop_output, 'w') as f:
	f.write(self.payload)

"""