#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <sys/stat.h>

#include <sysrepo.h>
// #include <sysrepo/plugins.h>
#include <sysrepo/values.h>
#include <sysrepo/xpath.h>
#include <libyang/libyang.h>

/* session of our plugin, can be used until cleanup is called */
    sr_session_ctx_t *sess;

/*******************************************************************************/


int modvers_dataprovider_cb(sr_session_ctx_t *session, const char *module_name, const char *path, const char *request_xpath,
                                   uint32_t request_id, struct lyd_node **parent, void *private_data) {
    // sr_val_t *v = NULL;
    // int rc = SR_ERR_OK;
    int rc;

    (void)session;
    (void)module_name;
    (void)path;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

if ( 0 > 1 ) {
    printf("module_name:   \"%s\"\n", module_name);
    printf("path:          \"%s\"\n", path);
    printf("request_xpath: \"%s\"\n", request_xpath);

    rc = sr_xpath_node_name_eq(request_xpath, "module");
    printf("rc: %d, \"%s\"\n", rc, "module");

    rc = sr_xpath_node_name_eq(request_xpath, "sysrepo-module-versions");
    printf("rc: %d, \"%s\"\n", rc, "sysrepo-module-versions");
    
    rc = sr_xpath_node_name_eq(request_xpath, "/sysrepo-module-versions");
    printf("rc: %d, \"%s\"\n", rc, "/sysrepo-module-versions");
    
    rc = sr_xpath_node_name_eq(request_xpath, "sysrepo-module-versions:sysrepo-module-versions");
    printf("rc: %d, \"%s\"\n", rc, "sysrepo-module-versions:sysrepo-module-versions");
    
    rc = sr_xpath_node_name_eq(request_xpath, "/sysrepo-module-versions:sysrepo-module-versions");
    printf("rc: %d, \"%s\"\n", rc, "/sysrepo-module-versions:sysrepo-module-versions");
    
    rc = sr_xpath_node_name_eq(request_xpath, "*");
    printf("rc: %d, \"%s\"\n", rc, "*");
    
    // if (sr_xpath_node_name_eq(path, "module")) {
}

    if (sr_xpath_node_name_eq(request_xpath, "*") ||
        (strcmp(path, "/sysrepo-module-versions:sysrepo-module-versions") == 0)) {

/* 
    <module>
      <name>ietf-interfaces</name>
      <revision>2018-02-20</revision>
      <source>github</source>
      <commit_id>6a93b0d09590c5631a776104a96929033cbb81e7</commit_id>
      <internal_version>1.0.0</internal_version>
    </module>
 */

        *parent = lyd_new_path(NULL, sr_get_context(sr_session_get_connection(sess)), "/sysrepo-module-versions:sysrepo-module-versions/module[name='ietf-interfaces']/revision", "2018-02-20", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ietf-interfaces']/source", "github", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ietf-interfaces']/commit_id", "6a93b0d09590c5631a776104a96929033cbb81e7", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ietf-interfaces']/internal_version", "1.0.0", 0, 0);


/* 
    <module>
      <name>ieee802-dot1q-preemption</name>
      <revision>2018-09-10</revision>
      <source>github</source>
      <commit_id>0add086a6e7af0d67a1f6deb8b773518650788e4</commit_id>
      <internal_version>1.0.0</internal_version>
    </module>

 */

        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-preemption']/revision", "2018-09-10", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-preemption']/source", "github", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-preemption']/commit_id", "0add086a6e7af0d67a1f6deb8b773518650788e4", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-preemption']/internal_version", "1.0.0", 0, 0);


/* 
    <module>
      <name>ieee802-dot1q-preempt</name>
      <revision>2018-03-29</revision>
      <source>proprietary</source>
      <internal_version>1.0.0</internal_version>
    </module>
 */

        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-preempt']/revision", "2018-03-29", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-preempt']/source", "proprietary", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-preempt']/internal_version", "1.0.0", 0, 0);


/* 
    <module>
      <name>ieee802-dot1ab-lldp</name>
      <revision>2018-11-11</revision>
      <source>github</source>
      <commit_id>0add086a6e7af0d67a1f6deb8b773518650788e4</commit_id>
      <internal_version>1.0.0</internal_version>
          <developer_change>Type of the leaf port/name changed to string.</developer_change>
          <developer_change>Type of the leafs port-id changed to string.</developer_change>
    </module>
 */

        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1ab-lldp']/revision", "2018-11-11", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1ab-lldp']/source", "github", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1ab-lldp']/commit_id", "0add086a6e7af0d67a1f6deb8b773518650788e4", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1ab-lldp']/internal_version", "1.0.0", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1ab-lldp']/developer_change", "Type of the leaf port/name changed to string.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1ab-lldp']/developer_change", "Type of the leafs port-id changed to string.", 0, 0);


/* 
    <module>
      <name>ieee802-dot1q-fqtss</name>
      <revision>2011-02-27</revision>
      <source>fromMIB</source>
      <internal_version>1.6.0</internal_version>
      <developer_change>YANG generated from MIB.</developer_change>
      <developer_change>ieee8021BridgeBaseComponentId and ieee8021BridgeBasePort objects are manualy added to yang module.</developer_change>
    </module>
 */
/* 
    <module>
      <name>ieee802-dot1q-fqtss</name>
      <revision>2011-02-27</revision>
      <source>fromMIB</source>
      <internal_version>1.0.0</internal_version>
      <developer_change>YANG generated from MIB.</developer_change>
      <developer_change>ieee8021BridgeBaseComponentId and ieee8021BridgeBasePort objects are manualy added to yang module.</developer_change>
    </module>
 */

        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-fqtss']/revision", "2011-02-27", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-fqtss']/source", "fromMIB", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-fqtss']/internal_version", "1.0.0", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-fqtss']/developer_change", "YANG generated from MIB.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-fqtss']/developer_change", "ieee8021BridgeBaseComponentId and ieee8021BridgeBasePort objects are manualy added to yang module.", 0, 0);


/* 
    <module>
      <name>ieee802-ethernet-interface</name>
      <revision>2019-06-21</revision>
      <source>github</source>
      <commit_id>38d20fa3d443fb4f3c3a44bfbeaf397b29a64740</commit_id>
      <internal_version>1.0.0</internal_version>
      <developer_change>Statement "default" commented for typedef 'duplex-type' used for leaf 'duplex'.</developer_change>
    </module>
 */

        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-ethernet-interface']/revision", "2019-06-21", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-ethernet-interface']/source", "github", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-ethernet-interface']/commit_id", "38d20fa3d443fb4f3c3a44bfbeaf397b29a64740", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-ethernet-interface']/internal_version", "1.0.0", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-ethernet-interface']/developer_change", "Statement \"default\" commented for typedef 'duplex-type' used for leaf 'duplex'.", 0, 0);


/* 
    <module>
      <name>ieee802-dot1q-bridge</name>
      <revision>2018-03-07</revision>
      <source>github</source>
      <commit_id>c3b7b1f01a044269b0496234deb8a051448c2f8c</commit_id>
      <internal_version>1.0.0</internal_version>
      <developer_change>"config false" added to the list /bridge-vlan/vlan.</developer_change>
      <developer_change>"config false" added to the list /bridge-vlan/vid-to-fid-allocation.</developer_change>
      <developer_change>"config false" added to the list /bridge-vlan/fid-to-vid-allocation.</developer_change>
          <developer_change>Leaf 'type-capabilties' renamed to 'type-capabilities'.</developer_change>
          <developer_change>The prefix 'dot1q' added when identity 'two-port-mac-relay-bridge' is used.</developer_change>
    </module>
 */

        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-bridge']/revision", "2018-03-07", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-bridge']/source", "github", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-bridge']/commit_id", "c3b7b1f01a044269b0496234deb8a051448c2f8c", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-bridge']/internal_version", "1.0.0", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-bridge']/developer_change", "\"config false\" added to the list /bridge-vlan/vlan.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-bridge']/developer_change", "\"config false\" added to the list /bridge-vlan/vid-to-fid-allocation.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-bridge']/developer_change", "\"config false\" added to the list /bridge-vlan/fid-to-vid-allocation.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-bridge']/developer_change", "Leaf 'type-capabilties' renamed to 'type-capabilities'.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-bridge']/developer_change", "The prefix 'dot1q' added when identity 'two-port-mac-relay-bridge' is used.", 0, 0);



/* 
    <module>
      <name>ieee802-dot1q-sched</name>
      <revision>2018-09-10</revision>
      <source>github</source>
      <commit_id>b8678ee9472189361b56899d4debd703102f7564</commit_id>
      <internal_version>1.6.0</internal_version>
      <developer_change>Statement "if-feature" commented.</developer_change>
      <developer_change>Import ieee802-dot1q-preemption commented because the preemption is not used in sched module when "if-feature" is commented.</developer_change>
      <developer_change>Statement "default" commented for all leafs with default value.</developer_change>
    </module>
 */
/* 
    <module>
      <name>ieee802-dot1q-sched</name>
      <revision>2018-09-10</revision>
      <source>github</source>
      <commit_id>0add086a6e7af0d67a1f6deb8b773518650788e4</commit_id>
      <internal_version>1.0.0</internal_version>
          <developer_change>The prefix 'sched' added when identities derived from base 'type-of-operation' is used.</developer_change>
    </module>
 */

        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-sched']/revision", "2018-09-10", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-sched']/source", "github", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-sched']/commit_id", "0add086a6e7af0d67a1f6deb8b773518650788e4", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-sched']/internal_version", "1.0.0", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1q-sched']/developer_change", "The prefix 'sched' added when identities derived from base 'type-of-operation' is used.", 0, 0);


/* 
    <module>
      <name>ieee8021-mstp</name>
      <revision>2012-08-10</revision>
      <source>fromMIB</source>
      <internal_version>1.8.0</internal_version>
      <developer_change>YANG generated from MIB.</developer_change>
      <developer_change>Leafs ieee8021MstpBridgePriority and ieee8021MstpPortPriority are modified and they have limited values in range 0-15.</developer_change>
      <developer_change>Import of SNMPv2-TC commented.</developer_change>
      <developer_change>Unimplemented objects commented.</developer_change>
      <developer_change>ieee8021MstpCistPortRole type modified: enum "disabled" added.</developer_change>
      <developer_change>ieee8021MstpPortState type modified: enum "discarding" added.</developer_change>
      <developer_change>ieee8021MstpPortRole type modified: enum "disabled" added.</developer_change>
      <developer_change>ieee8021MstpCistMaxHops range is changed from 6..40 into 10..255.</developer_change>
      <developer_change>leaf ieee8021MstpConfigurationName: length "32" is commented out</developer_change>
      <developer_change>Added leaf ieee8021MstpCistBridgePriority inside list ieee8021MstpCistEntry.</developer_change>
    </module>
 */

        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/revision", "2012-08-10", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/source", "fromMIB", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/internal_version", "1.8.0", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/developer_change", "YANG generated from MIB.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/developer_change", "Leafs ieee8021MstpBridgePriority and ieee8021MstpPortPriority are modified and they have limited values in range 0-15.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/developer_change", "Import of SNMPv2-TC commented.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/developer_change", "Unimplemented objects commented.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/developer_change", "ieee8021MstpCistPortRole type modified: enum \"disabled\" added.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/developer_change", "ieee8021MstpPortState type modified: enum \"discarding\" added.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/developer_change", "ieee8021MstpPortRole type modified: enum \"disabled\" added.", 0, 0);

        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/developer_change", "ieee8021MstpCistMaxHops range is changed from 6..40 into 10..255.", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/developer_change", "leaf ieee8021MstpConfigurationName: length \"32\" is commented out", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee8021-mstp']/developer_change", "Added leaf ieee8021MstpCistBridgePriority inside list ieee8021MstpCistEntry.", 0, 0);


/* 
    <module>
      <name>ietf-ptp</name>
      <revision>2018-09-10</revision>
      <source>standard_document</source>
      <internal_version>1.0.0</internal_version>
      <developer_change>The "config false" statement added to all objects for which modifications are not supported by liblldpctl.</developer_change>
    </module>
 */

        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ietf-ptp']/revision", "2018-09-10", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ietf-ptp']/source", "standard_document", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ietf-ptp']/internal_version", "1.0.0", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ietf-ptp']/developer_change", "The \"config false\" statement added to all objects for which modifications are not supported by liblldpctl.", 0, 0);


/* 
    <module>
      <name>ieee802-dot1CB</name>
      <revision>2019-04-17</revision>
      <source>standard_document</source>
      <internal_version>1.0.0</internal_version>
      <developer_change>Prefix of ieee802-dot1q-bridge module changed from dot1q-bridge to dot1q.</developer_change>
    </module>
 */

        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1CB']/revision", "2019-04-17", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1CB']/source", "standard_document", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1CB']/internal_version", "1.0.0", 0, 0);
        lyd_new_path(*parent, NULL, "/sysrepo-module-versions:sysrepo-module-versions/module[name='ieee802-dot1CB']/developer_change", "Prefix of ieee802-dot1q-bridge module changed from dot1q-bridge to dot1q.", 0, 0);


    } else {
        printf("GENERAL XP: %s\n", request_xpath);

    }

    return SR_ERR_OK;
}

/* Registers for providing of operational data under given xpath. */
int sr_plugin_init_cb(sr_session_ctx_t *session, void **private_data) {
    /* remember the session of our plugin */
    sess = session;

    sr_subscription_ctx_t *subscription = NULL;
    sr_subscription_ctx_t *subscription_oper = NULL;
    int rc = SR_ERR_OK;

    // operational data
    rc = sr_oper_get_items_subscribe(session, "sysrepo-module-versions", "/sysrepo-module-versions:sysrepo-module-versions", modvers_dataprovider_cb, NULL, SR_SUBSCR_DEFAULT, &subscription_oper);
    if (SR_ERR_OK != rc) goto error;

    syslog(LOG_DEBUG, "plugin initialized successfully.");

    /* set subscription as our private context */
    // how to preserve both of them?
    *private_data = subscription;

    return SR_ERR_OK;

error:
    syslog(LOG_ERR, "plugin initialization failed: %s", sr_strerror(rc));
    if (subscription != NULL) sr_unsubscribe(subscription);
    if (subscription_oper != NULL) sr_unsubscribe(subscription_oper);
    return rc;
}

void sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data) {
    (void)session;
    (void)private_data;
    /* subscription was set as our private context */
    sr_unsubscribe((sr_subscription_ctx_t *)private_data);
    syslog(LOG_DEBUG, "plugin cleanup finished");
}
