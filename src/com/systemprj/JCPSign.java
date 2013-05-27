package com.systemprj;

import javax.jws.WebMethod;
import javax.jws.WebService;
import javax.jws.soap.SOAPBinding;
import javax.jws.soap.SOAPBinding.Style;

//Service Endpoint Interface
@WebService
@SOAPBinding(style = Style.RPC)
public interface JCPSign {

	@WebMethod public String signXML(String document)throws Exception;
    @WebMethod public String signXML2(String document)throws Exception;
    @WebMethod public String signTest()throws Exception;
}