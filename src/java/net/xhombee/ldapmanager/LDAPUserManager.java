/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package net.xhombee.ldapmanager;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.directory.Attribute;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.naming.Context;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.DirContext;
import javax.naming.directory.Attributes;
import javax.naming.NamingException;
import java.util.Hashtable;
import java.util.Map;
import java.util.Vector;
import javax.naming.NameClassPair;
import javax.naming.NamingEnumeration;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

/**
 *
 * @author bear
 */
public class LDAPUserManager extends HttpServlet {

    /** 
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code> methods.
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    DirContext ctx;
    PrintWriter out;
    String base = "";
    String path = "";

    /**
     *
     * @param request
     * @param response
     * @throws ServletException
     * @throws IOException
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        out = response.getWriter();
        Hashtable<String, String> env = new Hashtable<String, String>(11);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, this.getServletConfig().getInitParameter("ldapurl"));
        env.put(Context.SECURITY_PRINCIPAL, this.getServletConfig().getInitParameter("ldapuser"));
        env.put(Context.SECURITY_CREDENTIALS, this.getServletConfig().getInitParameter("ldappasswd"));
        base = this.getServletConfig().getInitParameter("ldapbase");
        String username = "bear";
        path = this.getServletContext().getContextPath() + request.getServletPath();
        if (request.getParameter("username") != null) {
            username = request.getParameter("username");
        }
        try {

            out.println("<html>");
            out.println("<head>");
            out.println("<title>ldap user manager</title>");
            out.println("</head>");
            out.println("<body>");
            out.println("<h1>ldap tester at " + path + "</h1>");

            // Create the initial directory context
            ctx = new InitialDirContext(env);

            // Navigation header
            out.println("<a href=\"" + path + "?action=listUsers\">Users</a>");
            out.println("<a href=\"" + path + "?action=listUnixGroups\">Unix Groups</a>");
            out.println("<a href=\"" + path + "?action=listHostGroups\">Host Groups</a>");
            out.println("<a href=\"" + path + "?action=listWebGroups\">Web Roles</a>");
            out.println("<a href=\"" + path + "?action=listAutomounts\">AutoMounts</a>");
            out.println("<br><hr><br>");
            Map requestMap = request.getParameterMap();
            if (requestMap.containsKey("action")) {
                String action = ((String[]) requestMap.get("action"))[0];
                if (action != null) {
                    //out.println("Action to be performed is " + action);
                    if (action.equals("setGroupsForUser")) {
                        String userDN = request.getParameter("userDN");
                        String groupOU = request.getParameter("groupOU");
                        Vector<String> groupsForUser = new Vector<String>(Arrays.asList(request.getParameterValues("groupsForUser")));
                        setGroupsForUser(userDN, groupOU, groupsForUser);
                        printAttrs(userDN);
                        printGroupsForUserForm(userDN, "ou=Group," + base);
                        printGroupsForUserForm(userDN, "ou=HostGroups," + base);
                        printGroupsForUserForm(userDN, "ou=Roles," + base);
                    }
                    if (action.equals("setUsersForGroup")) {
                        String groupDN = request.getParameter("groupDN");
                        String peopleOU = request.getParameter("peopleOU");
                        Vector<String> usersForGroup = new Vector<String>(Arrays.asList(request.getParameterValues("usersForGroup")));
                        setUsersForGroup(groupDN, peopleOU, usersForGroup);
                        printAttrs(groupDN);
                        printUsersForGroupForm(groupDN, peopleOU);
                    }
                    if (action.equals("listGroup")) {
                        String groupDN = request.getParameter("groupDN");
                        printAttrs(groupDN);
                        printUsersForGroupForm(groupDN, "ou=People," + base);
                    }
                    if (action.equals("listUser")) {
                        out.println("Requested to list user");
                        String userDN = request.getParameter("userDN");
                        printAttrs(userDN);
                        printGroupsForUserForm(userDN, "ou=Group," + base);
                        printGroupsForUserForm(userDN, "ou=HostGroups," + base);
                        printGroupsForUserForm(userDN, "ou=Roles," + base);
                    }
                    if (action.equals("listAutomount")) {
                        String automountOU = "automountMapName=auto.home," + base;
                        String automountDN = request.getParameter("automountDN");
                        printAttrs(automountDN);
                        printAutomountsForm(automountOU);
                    }
                    if (action.equals("listUnixGroups")) {
                        String groupOU = "ou=Group," + base;
                        printGroupsForm(groupOU);
                    }
                    if (action.equals("listHostGroups")) {
                        String groupOU = "ou=HostGroups," + base;
                        printGroupsForm(groupOU);
                    }
                    if (action.equals("listWebGroups")) {
                        String groupOU = "ou=Roles," + base;
                        printGroupsForm(groupOU);
                    }
                    if (action.equals("listUsers")) {
                        String peopleOU = "ou=People," + base;
                        printUsersForm(peopleOU);
                    }
                    if (action.equals("listAutomounts")) {
                        String automountOU = "automountMapName=auto.home," + base;
                        printAutomountsForm(automountOU);
                    }
                    if (action.equals("confirmAutomountDelete")) {
                        String automountDN = request.getParameter("automountDN");
                        printConfirmAutomountDeleteForm(automountDN);
                    }
                    if (action.equals("confirmGroupDelete")) {
                        String groupDN = request.getParameter("groupDN");
                        printConfirmGroupDeleteForm(groupDN);
                    }
                    if (action.equals("confirmUserDelete")) {
                        String userDN = request.getParameter("userDN");
                        printConfirmUserDeleteForm(userDN);
                    }
                    if (action.equals("confirmedAutomountDelete")) {
                        String automountDN = request.getParameter("automountDN");
                        deleteAutomount(automountDN);
                        String automountOU = automountDN.replaceFirst("automountKey=[^,]*,", "");
                        printAutomountsForm(automountOU);
                    }
                    if (action.equals("confirmedGroupDelete")) {
                        String groupDN = request.getParameter("groupDN");
                        deleteGroup(groupDN);
                        String groupOU = groupDN.replaceFirst("cn=[^,]*,", "");
                        printGroupsForm(groupOU);
                    }
                    if (action.equals("confirmedUserDelete")) {
                        String userDN = request.getParameter("userDN");
                        deleteUser(userDN);
                        String peopleOU = userDN.replaceFirst("uid=[^,]*,", "");
                        printUsersForm(peopleOU);
                    }
                    if (action.equals("createAutomount")) {
                        String automountKey = request.getParameter("automountKey");
                        String automountInformation = request.getParameter("automountInformation");
                        String automountOU = request.getParameter("automountOU");
                        createAutomount(automountKey, automountInformation, automountOU);
                        printAutomountsForm(automountOU);
                    }
                    if (action.equals("createGroup")) {
                        String group = request.getParameter("group");
                        String parentOU = request.getParameter("parentOU");
                        createGroup(group, parentOU);
                        printGroupsForm(parentOU);
                    }
                    if (action.equals("createUser")) {
                        String user = request.getParameter("user");
                        String password = request.getParameter("password");
                        String parentOU = request.getParameter("parentOU");
                        createUser(user, password, parentOU);
                        printUsersForm(parentOU);
                    }
                } else {
                    out.println("action was null");
                }
            } else {
                //out.println("action parameter not provided");
            }

            
            ctx.close();
            out.println("</body>");
            out.println("</html>");

        } catch (NamingException e) {
            out.println("Problem getting attribute: " + e + "<br>");
            out.println("<!--");
            e.printStackTrace(out);
            out.println("-->");
        } finally {
            out.close();
        }
    }

// <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

    void printConfirmAutomountDeleteForm(String automountDN) {
        out.println("Are you sure you want to delete automount " + automountDN + " ?");
        out.println("<form action=\"" + path + "\" method=\"post\">");
        out.print("<input type=\"hidden\" name=\"action\" value=\"confirmedAutomountDelete\">");
        out.print("<input type=\"hidden\" name=\"automountDN\" value=\"" + automountDN + "\">");
        out.print("<input type=\"submit\" value=\"Yes\">");
        out.print("</form>");
    }

    void printConfirmGroupDeleteForm(String groupDN) {
        out.println("Are you sure you want to delete group " + groupDN + " ?");
        out.println("<form action=\"" + path + "\" method=\"post\">");
        out.print("<input type=\"hidden\" name=\"action\" value=\"confirmedGroupDelete\">");
        out.print("<input type=\"hidden\" name=\"groupDN\" value=\"" + groupDN + "\">");
        out.print("<input type=\"submit\" value=\"Yes\">");
        out.print("</form>");
    }

    void printConfirmUserDeleteForm(String userDN) {
        out.println("Are you sure you want to delete user " + userDN + " ?");
        out.println("<form action=\"" + path + "\" method=\"post\">");
        out.print("<input type=\"hidden\" name=\"action\" value=\"confirmedUserDelete\">");
        out.print("<input type=\"hidden\" name=\"userDN\" value=\"" + userDN + "\">");
        out.print("<input type=\"submit\" value=\"Yes\">");
        out.print("</form>");
    }

    void printAttrs(String name) throws NamingException {
        out.println("List of Attributues for " + name + "<br>");
        Attributes attrs = ctx.getAttributes(name);
        NamingEnumeration attrIDs = attrs.getIDs();
        out.println("<table border=1>");
        while (attrIDs.hasMore()) {
            String attrID = (String) attrIDs.next();
            Attribute values = attrs.get(attrID);
            for (int i = 0; i < values.size(); i++) {
                if (values.get(i) != null) {
                    out.println("<tr><td>" + attrID + "</td><td>" + values.get(i).toString() + "</td></tr>");
                }
            }
        }
        out.println("</table><br>");
    }

    void printGroups(String name) throws NamingException {
        out.println("List of sub contexts<br>");
        NamingEnumeration roles = ctx.list(name);
        while (roles.hasMore()) {
            NameClassPair nc = (NameClassPair) roles.next();
            out.println(nc.getName() + "<br>");
        }
        out.println("<br>");
    }

    void printAutomountsForm(String automountOU) throws NamingException {
        out.println("automounts under " + automountOU + "<br>");
        NamingEnumeration<NameClassPair> automounts = ctx.list(automountOU);
        out.println("<table border=1>");
        while (automounts.hasMore()) {
            NameClassPair nc = automounts.next();

            out.println("<tr><td><a href=\"" + path + "?action=listAutomount&automountDN=" + encode(nc.getNameInNamespace()) + "\">" + nc.getName() + "</a></td><td><a href=\"" + path + "?action=confirmAutomountDelete&automountDN=" + encode(nc.getNameInNamespace()) + "\">delete</a></td></tr>");
        }
        out.println("</table><br>");
        out.println("Create Automount<br>");
        out.println("<form action=\"" + path + "\" method=\"post\">");
        out.println("<input type=\"hidden\" name=\"action\" value=\"createAutomount\">");
        out.println("<input type=\"hidden\" name=\"automountOU\" value=\"" + automountOU + "\">");
        out.println("<table>");
        out.println("<tr><td>AutomountKey</td><td><input type=\"text\" name=\"automountKey\"></td></tr>");
        out.println("<tr><td>AutomountInformation</td><td><input type=\"text\" name=\"automountInformation\"></td></tr>");
        out.println("</table>");
        out.println("<input type=\"submit\">");
        out.println("</form>");
    }

    void printGroupsForm(String groupOU) throws NamingException {
        out.println("Groups under " + groupOU + "<br>");
        NamingEnumeration<NameClassPair> groups = ctx.list(groupOU);
        out.println("<table border=1>");
        while (groups.hasMore()) {
            NameClassPair nc = groups.next();

            out.println("<tr><td><a href=\"" + path + "?action=listGroup&groupDN=" + encode(nc.getNameInNamespace()) + "\">" + nc.getName() + "</a></td><td><a href=\"" + path + "?action=confirmGroupDelete&groupDN=" + encode(nc.getNameInNamespace()) + "\">delete</a></td></tr>");
        }
        out.println("</table><br>");
        out.println("Create Group<br>");
        out.println("<form action=\"" + path + "\" method=\"post\">");
        out.println("<input type=\"hidden\" name=\"action\" value=\"createGroup\">");
        out.println("<input type=\"hidden\" name=\"parentOU\" value=\"" + groupOU + "\">");
        out.println("<input type=\"text\" name=\"group\">");
        out.println("<input type=\"submit\">");
        out.println("</form>");
    }

    void printUsersForm(String peopleOU) throws NamingException {
        out.println("Users under " + peopleOU + "<br>");
        NamingEnumeration<NameClassPair> users = ctx.list(peopleOU);
        out.println("<table border=1>");
        while (users.hasMore()) {
            NameClassPair nc = users.next();

            out.println("<tr><td><a href=\"" + path + "?action=listUser&userDN=" + encode(nc.getNameInNamespace()) + "\">" + nc.getName() + "</a></td><td><a href=\"" + path + "?action=confirmUserDelete&userDN=" + encode(nc.getNameInNamespace()) + "\">delete</a></td></tr>");
        }
        out.println("</table><br>");
        out.println("Create User<br>");
        out.println("<form action=\"" + path + "\" method=\"post\">");
        out.println("<input type=\"hidden\" name=\"action\" value=\"createUser\">");
        out.println("<input type=\"hidden\" name=\"parentOU\" value=\"" + peopleOU + "\">");
        out.println("<table>");
        out.println("<tr><td>Username</td><td><input type=\"text\" name=\"user\"></td></tr>");
        out.println("<tr><td>Password</td><td><input type=\"text\" name=\"password\"></td></tr>");
        out.println("</table>");
        out.println("<input type=\"submit\">");
        out.println("</form>");
    }

    void createAutomount(String automountKey,String automountInformation, String automountOU) throws NamingException {
        BasicAttributes newAutomount = new BasicAttributes();
        BasicAttribute objectClass = new BasicAttribute("objectClass");
        objectClass.add("top");
        objectClass.add("automount");
        newAutomount.put(objectClass);
        newAutomount.put("automountKey", automountKey);
        newAutomount.put("automountInformation", automountInformation);
        
        ctx.createSubcontext("automountKey=" + automountKey + "," + automountOU, newAutomount);
    }

    void createGroup(String group, String parentOU) throws NamingException {
        BasicAttributes newGroup = new BasicAttributes();
        BasicAttribute objectClass = new BasicAttribute("objectClass");
        objectClass.add("top");
        objectClass.add("groupOfUniqueNames");
        objectClass.add("posixGroup");
        newGroup.put(objectClass);
        newGroup.put("cn", group);
        newGroup.put("uniqueMember", "cn=" + group + "," + parentOU);
        newGroup.put("gidNumber", Integer.toString(nextGid(parentOU)));
        ctx.createSubcontext("cn=" + group + "," + parentOU, newGroup);
    }

    void createUser(String user, String password, String parentOU) throws NamingException {
        BasicAttributes newUser = new BasicAttributes();
        BasicAttribute objectClass = new BasicAttribute("objectClass");
        objectClass.add("top");
        objectClass.add("inetOrgPerson");
        objectClass.add("posixAccount");
        newUser.put(objectClass);
        newUser.put("uid", user);
        newUser.put("cn", user);
        newUser.put("sn", user);
        newUser.put("givenName", user);
        newUser.put("gidNumber", "100");
        newUser.put("homeDirectory", "/home/" + user);
        newUser.put("loginShell", "/bin/bash");
        newUser.put("userPassword", password);
        newUser.put("uidNumber", Integer.toString(nextUid(parentOU)));
        ctx.createSubcontext("uid=" + user + "," + parentOU, newUser);
    }

    void deleteAutomount(String automountDN) throws NamingException {
        ctx.destroySubcontext(automountDN);
    }

    void deleteGroup(String groupDN) throws NamingException {
        ctx.destroySubcontext(groupDN);
    }

    void deleteUser(String userDN) throws NamingException {
        ctx.destroySubcontext(userDN);
    }

    int nextGid(String groupOU) throws NamingException {
        return nextGid(groupOU, 0, Integer.MAX_VALUE);
    }

    int nextGid(String groupOU, int min, int max) throws NamingException {
        int r = min;
        String[] gidAttrs = {"gidNumber", "cn"};
        NamingEnumeration groups = ctx.list(groupOU);
        String topGroup = "";
        while (groups.hasMore()) {
            NameClassPair nc = (NameClassPair) groups.next();
            Attributes gidAndName = ctx.getAttributes(nc.getNameInNamespace(), gidAttrs);
            int currentGid = Integer.parseInt(gidAndName.get("gidNumber").get().toString());
            if ((currentGid > r) & (currentGid < max)) {
                r = currentGid;
                topGroup = nc.getNameInNamespace();
            }

        }
        //out.println(topGroup + " has gidNUmber: " + r + "<br>");
        return r + 1;
    }

    int nextUid(String userOU) throws NamingException {
        return nextUid(userOU, 0, Integer.MAX_VALUE);
    }

    int nextUid(String userOU, int min, int max) throws NamingException {
        int r = min;
        String[] uidAttrs = {"uidNumber", "cn"};
        NamingEnumeration users = ctx.list(userOU);
        String topUser = "";
        while (users.hasMore()) {
            NameClassPair nc = (NameClassPair) users.next();
            Attributes uidAndName = ctx.getAttributes(nc.getNameInNamespace(), uidAttrs);
            int currentUid = Integer.parseInt(uidAndName.get("uidNumber").get().toString());
            if ((currentUid > r) & (currentUid < max)) {
                r = currentUid;
                topUser = nc.getNameInNamespace();
            }

        }
        //out.println(topUser + " has uidNUmber: " + r + "<br>");
        return r + 1;
    }

    Hashtable<String, Boolean> getGroupsForUser(String userDN, String groupOU) throws NamingException {
        Hashtable<String, Boolean> groupPresence = new Hashtable<String, Boolean>();
        NamingEnumeration<NameClassPair> groups = ctx.list(groupOU);
        //String uid = userDN.substring(userDN.indexOf('=') + 1, userDN.indexOf(','));
        //out.println("uid: " + uid + " <br>");
        while (groups.hasMore()) {
            NameClassPair nc = groups.next();
            Attributes attrs = ctx.getAttributes(nc.getNameInNamespace());
            Attribute memberUid = attrs.get("uniqueMember");
            boolean inGroup = false;
            if (memberUid != null) {
                NamingEnumeration memberUids = attrs.get("uniqueMember").getAll();

                while (memberUids.hasMore()) {
                    String member = memberUids.next().toString();
                    if (member.equals(userDN)) {
                        inGroup = true;
                    }
                }

            }
            groupPresence.put(nc.getNameInNamespace(), inGroup);
        }
        return groupPresence;
    }

    Hashtable<String, Boolean> getUsersForGroup(String groupDN, String peopleOU) throws NamingException {
        Hashtable<String, Boolean> userPresence = new Hashtable<String, Boolean>();
        NamingEnumeration<NameClassPair> users = ctx.list(peopleOU);
        Attributes groupAttrs = ctx.getAttributes(groupDN);
        Vector uniqueMembers = new Vector();
        if (groupAttrs.get("uniqueMember") != null) {
            NamingEnumeration uniqueMembersNE = groupAttrs.get("uniqueMember").getAll();
            while (uniqueMembersNE.hasMore()) {
                Object tmp = uniqueMembersNE.next();
                if (tmp != null) {
                    uniqueMembers.add(tmp);
                }
            }
        }
        while (users.hasMore()) {
            NameClassPair nc = (NameClassPair) users.next();
            String userDN = nc.getNameInNamespace();
            boolean inGroup = false;
            if (uniqueMembers.contains(userDN)) {
                inGroup = true;
            }
            userPresence.put(nc.getNameInNamespace(), inGroup);
        }
        return userPresence;
    }

    void printGroupsForUserForm(String userDN, String groupOU) throws NamingException {
        out.println("group listing for " + userDN + " in group set " + groupOU + "<br>");
        Hashtable groupPresence = getGroupsForUser(userDN, groupOU);
        Enumeration groups = groupPresence.keys();
        out.println("<form><table border=1>");
        out.println("<input type=hidden name=\"action\" value=\"setGroupsForUser\" >");
        out.println("<input type=hidden name=\"userDN\" value=\"" + userDN + "\" >");
        out.println("<input type=hidden name=\"groupOU\" value=\"" + groupOU + "\" >");
        while (groups.hasMoreElements()) {
            String groupDN = groups.nextElement().toString();
            String checked = "";
            if ((Boolean) groupPresence.get(groupDN)) {
                checked = " checked ";
            }
            out.println("<tr><td>" + groupDN + "</td><td><input type=checkbox name= \"groupsForUser\" value=\"" + groupDN + "\" " + checked + "</td></tr>");
        }
        out.println("</table>");
        out.println("<input type=\"submit\">");
        out.println("</form>");
        out.println("<br>");
    }

    void printUsersForGroupForm(String groupDN, String peopleOU) throws NamingException {
        out.println("User listing for " + peopleOU + " in group " + groupDN + "<br>");
        Hashtable userPresence = getUsersForGroup(groupDN, peopleOU);
        Enumeration users = userPresence.keys();
        out.println("<form><table border=1>");
        out.println("<input type=hidden name=\"action\" value=\"setUsersForGroup\" >");
        out.println("<input type=hidden name=\"groupDN\" value=\"" + groupDN + "\" >");
        out.println("<input type=hidden name=\"peopleOU\" value=\"" + peopleOU + "\" >");
        while (users.hasMoreElements()) {
            String userDN = users.nextElement().toString();
            String checked = "";
            if ((Boolean) userPresence.get(userDN)) {
                checked = " checked ";
            }
            out.println("<tr><td>" + userDN + "</td><td><input type=checkbox name= \"usersForGroup\" value=\"" + userDN + "\" " + checked + "</td></tr>");
        }
        out.println("</table>");
        out.println("<input type=\"submit\">");
        out.println("</form>");
        out.println("<br>");
    }

    void setGroupsForUser(String userDN, String groupOU, Vector groupsForUser) throws NamingException {

        NamingEnumeration groups = ctx.list(groupOU);
        //String uid = userDN.substring(userDN.indexOf('=') + 1, userDN.indexOf(','));
        //out.println("uid: " + uid + " <br>");
        while (groups.hasMore()) {
            NameClassPair nc = (NameClassPair) groups.next();
            String groupDN = nc.getNameInNamespace();
            Attributes attrs = ctx.getAttributes(groupDN);
            Attribute memberEntry = attrs.get("uniqueMember");
            boolean inGroup = false;
            if (memberEntry != null) {
                NamingEnumeration memberEntries = attrs.get("uniqueMember").getAll();
                while (memberEntries.hasMore()) {
                    String member = memberEntries.next().toString();
                    if (member.equals(userDN)) {
                        inGroup = true;
                    }
                }

            }
            boolean shouldBeInGroup = groupsForUser.contains(groupDN);
            if (inGroup && !shouldBeInGroup) {
                removeUserFromGroup(userDN, groupDN);
            }
            if (!inGroup && shouldBeInGroup) {
                addUserToGroup(userDN, groupDN);
            }
        }

    }

    void setUsersForGroup(String groupDN, String peopleOU, Vector usersInGroup) throws NamingException {

        NamingEnumeration users = ctx.list(peopleOU);
        while (users.hasMore()) {
            NameClassPair nc = (NameClassPair) users.next();
            String userDN = nc.getNameInNamespace();
            Attributes attrs = ctx.getAttributes(groupDN);
            Attribute memberEntry = attrs.get("uniqueMember");
            boolean inGroup = false;
            if (memberEntry != null) {
                NamingEnumeration memberEntries = attrs.get("uniqueMember").getAll();
                while (memberEntries.hasMore()) {
                    String member = memberEntries.next().toString();
                    if (member.equals(userDN)) {
                        inGroup = true;
                    }
                }
            }
            boolean shouldBeInGroup = usersInGroup.contains(userDN);
            if (inGroup && !shouldBeInGroup) {
                removeUserFromGroup(userDN, groupDN);
            }
            if (!inGroup && shouldBeInGroup) {
                addUserToGroup(userDN, groupDN);
            }
        }

    }

    void addUserToGroup(String userDN, String groupDN) throws NamingException {
        ctx.modifyAttributes(groupDN, DirContext.ADD_ATTRIBUTE, new BasicAttributes("uniqueMember", userDN));
    }

    void removeUserFromGroup(String userDN, String groupDN) throws NamingException {
        ctx.modifyAttributes(groupDN, DirContext.REMOVE_ATTRIBUTE, new BasicAttributes("uniqueMember", userDN));
    }

    String encode(String stuff) {
        String r = "";

        try {
            r = URLEncoder.encode(stuff, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(LDAPUserManager.class.getName()).log(Level.SEVERE, null, ex);
        }

        return r;
    }
}
