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

/**
 * A {@link LookupStrategy} that generated a fallback {@link Acl}
 * when no {@link Acl} for an {@link ObjectIdentity} is found in the database.
 *
 * <p>
 * A {@link OwnerResolver} and a {@link ParentResolver} should be injected into this {@link FallbackLookupStrategy}
 * to determine the {@link Acl#getOwner() owner} and the {@link Acl#getParentAcl() parent} of the generated {@link Acl}.
 * </p>
 */
@AllArgsConstructor
public class FallbackLookupStrategy implements LookupStrategy {

    private final LookupStrategy previousStrategy;
    private final PermissionGrantingStrategy permissionGrantingStrategy;
    private final OwnerResolver ownerResolver;
    private final ParentResolver parentResolver;

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

    public interface OwnerResolver {
        Optional<Sid> resolveOwner(ObjectIdentity objectIdentity);
    }

    public interface ParentResolver {
        Optional<ObjectIdentity> resolveParent(ObjectIdentity objectIdentity);
    }

}