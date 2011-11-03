package ua.gradsoft.rlmprototest;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.freeradius.Vsa;
import org.freeradius.Vsa.RequestData;

/**
 *Example of servlet.
 * @author rssh
 */
public class RlmEndpointServlet extends HttpServlet
{

    @Override
    protected void doPut(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
       RequestData requestData = Vsa.RequestData.parseFrom(request.getInputStream());
       System.err.println(
               String.format("data received: state=%s",requestData.getState().toString()));
       for(Vsa.ValuePair vp : requestData.getVpsList()) {
           System.err.print("("+vp.getAttribute()+")");
       }
       Map<Integer,Vsa.ValuePair> map = createMap(requestData.getVpsList());
       Vsa.RequestDataReply.Builder replyBuilder = Vsa.RequestDataReply.newBuilder();
       if (requestData.getState() == Vsa.ProcessingState.AUTHORIZE
         || requestData.getState() == Vsa.ProcessingState.AUTHENTICATE ) {
          Vsa.ValuePair userNameVp = map.get(RadiusConstants.PW_USER_NAME);
          if (userNameVp!=null && userNameVp.getStringValue().equals("qqq")) {
              System.err.print("set allow to true");
              replyBuilder.setAllow(true);
          }else{
              replyBuilder.setAllow(false);
          }
       }
       if (requestData.getState()==Vsa.ProcessingState.POSTAUTH) {
          replyBuilder.addActions(
               Vsa.ValuePairAction.newBuilder().setOp(Vsa.ValuePairOp.ADD)
                                               .setVp(Vsa.ValuePair.newBuilder()
                                                       .setAttribute(RadiusConstants.PW_FRAMED_IP_ADDRESS)
                                                       .setIpv4AddrValue(this.ipaddr(10,1,2,3))
                                                       .build()
                                               ).build()
          );
       }
       Vsa.RequestDataReply reply = replyBuilder.build();
       reply.writeTo(response.getOutputStream());
       response.getOutputStream().flush();
    }
    
    // note, that this is 'example'. I.e. serios implementation must
    // index by (attribute, vendor), not only by attribute.
    private Map<Integer,Vsa.ValuePair> createMap(List<Vsa.ValuePair> pairs)
    {
      Map<Integer,Vsa.ValuePair> retval = new TreeMap<Integer,Vsa.ValuePair>();  
      for(Vsa.ValuePair pair: pairs) {
          retval.put(pair.getAttribute(), pair);
      }  
      return retval;
    }
    
    private int ipaddr(int x1, int x2, int x3, int x4)
    {  
      byte[] ba = new byte[4];
      ba[0]=(byte)x1;
      ba[1]=(byte)x2;
      ba[2]=(byte)x3;
      ba[3]=(byte)x4;
      try {
        InetAddress addr = java.net.Inet4Address.getByAddress(ba);
        System.err.println("hostaddress is:" + addr.getHostAddress());
        ba = addr.getAddress();  
      } catch(UnknownHostException ex) {
          System.err.println("Can't create address: "+ex.toString());
          return 0;
      }
      return (((((x1<<8)+x2)<<8)+x3)<<8)+x4;  
    }
    
}
