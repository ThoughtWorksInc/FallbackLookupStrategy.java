package com.thoughtworks.spring.security.acls.jdbc;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Collections.emptyList;
import static java.util.Collections.singletonList;
import static java.util.function.Function.identity;
import static java.util.stream.Collectors.toMap;

@AllArgsConstructor
public class FallbackLookupStrategy implements LookupStrategy {

    private final LookupStrategy previousStrategy;
    private final PermissionGrantingStrategy permissionGrantingStrategy;
    private final OwnerResolver ownerResolver;
    private final ParentResolver parentResolver;

    @Override
    public Map<ObjectIdentity, Acl> readAclsById(List<ObjectIdentity> objects, List<Sid> sids) {
        final Map<ObjectIdentity, Acl> acls = previousStrategy.readAclsById(objects, sids);
        return objects.stream().collect(toMap(
                identity(),
                objectIdentity -> {
                    final Optional<Acl> optionalAcl = Optional.ofNullable(acls.get(objectIdentity));
                    return optionalAcl.orElseGet(() -> new Acl() {
                        @Getter(lazy = true)
                        private final Sid owner = ownerResolver.resolveOwner(objectIdentity).orElse(null);

                        @Getter(lazy = true)
                        private final Acl parentAcl =
                                parentResolver.resolveParent(objectIdentity)
                                        .map(this::readAcl)
                                        .orElse(null);

                        private Acl readAcl(ObjectIdentity objectIdentity) {
                            return readAclsById(singletonList(objectIdentity), sids).get(objectIdentity);
                        }

                        public List<AccessControlEntry> getEntries() {
                            return emptyList();
                        }

                        public ObjectIdentity getObjectIdentity() {
                            return objectIdentity;
                        }

                        public boolean isEntriesInheriting() {
                            return true;
                        }

                        public boolean isGranted(List<Permission> permission, List<Sid> sids, boolean administrativeMode) throws NotFoundException, UnloadedSidException {
                            return permissionGrantingStrategy.isGranted(this, permission, sids, administrativeMode);
                        }

                        public boolean isSidLoaded(List<Sid> sids) {
                            return true;
                        }
                    });
                }
        ));
    }

    interface OwnerResolver {
        Optional<Sid> resolveOwner(ObjectIdentity objectIdentity);
    }

    interface ParentResolver {
        Optional<ObjectIdentity> resolveParent(ObjectIdentity objectIdentity);
    }

}