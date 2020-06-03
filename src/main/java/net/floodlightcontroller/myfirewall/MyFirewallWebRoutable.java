package net.floodlightcontroller.myfirewall;

import net.floodlightcontroller.restserver.RestletRoutable;
import org.restlet.Context;
import org.restlet.routing.Router;

public class MyFirewallWebRoutable implements RestletRoutable {
    @Override
    public Router getRestlet(Context context) {
        Router router = new Router(context);
        router.attach("/rules/json", MyFirewallResource.class);
        return router;
    }

    @Override
    public String basePath() {
        return "/wm/myfirewall";
    }
}
