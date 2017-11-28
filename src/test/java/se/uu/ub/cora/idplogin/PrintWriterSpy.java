package se.uu.ub.cora.idplogin;

import java.io.OutputStream;
import java.io.PrintWriter;

public class PrintWriterSpy extends PrintWriter {

	public PrintWriterSpy(OutputStream out) {
		super(out);
	}

}
